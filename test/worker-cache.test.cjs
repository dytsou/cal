const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const workerSource = fs.readFileSync(path.join(__dirname, '..', 'worker.js'), 'utf8');

function loadWorker(runtime) {
  const context = {
    atob,
    Buffer,
    console,
    crypto: webcrypto,
    Headers,
    Request,
    Response,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    fetch: (...args) => runtime.fetch(...args),
    caches: {
      get default() {
        return runtime.cache;
      },
    },
    module: { exports: {} },
  };
  const transformedSource =
    workerSource.replace('export default {', 'const worker = {') +
    '\nmodule.exports.worker = worker;';
  vm.runInNewContext(transformedSource, context, { filename: 'worker.js' });
  return context.module.exports.worker;
}

class MemoryCache {
  constructor() {
    this.entries = new Map();
    this.matchCalls = [];
    this.putCalls = [];
  }

  async match(request) {
    this.matchCalls.push(request);
    const entry = this.entries.get(request.url);
    return entry ? entry.clone() : undefined;
  }

  async put(request, response) {
    this.putCalls.push({ request, response: response.clone() });
    this.entries.set(request.url, response.clone());
  }

  async markStale(age = 10 * 60 * 1000 + 1000) {
    const [key, response] = this.entries.entries().next().value || [];
    if (!key || !response) {
      throw new Error('No cache entry to age');
    }
    const headers = new Headers(response.headers);
    headers.set('X-Calendar-Cache-Stored-At', String(Date.now() - age));
    this.entries.set(
      key,
      new Response(await response.clone().arrayBuffer(), {
        status: response.status,
        headers,
      })
    );
  }
}

function makeContext() {
  const waitUntilPromises = [];
  return {
    waitUntil(promise) {
      waitUntilPromises.push(Promise.resolve(promise));
    },
    async flush() {
      await Promise.all(waitUntilPromises.splice(0));
    },
  };
}

function makeEnvironment() {
  return {
    CACHE_IDENTITY_SECRET: 'cache-identity-secret',
    CALENDAR_URL: 'https://calendar.example.test/private.ics',
    ENCRYPTION_KEY: '',
    USER_EMAILS: 'owner@example.test',
  };
}

function makeHtml(version, sourceUrl = 'https://calendar.example.test/private.ics') {
  return '<html><head></head><body><main>' + version + ' ' + sourceUrl + '</main></body></html>';
}

function makeResponse(
  body,
  { status = 200, contentType = 'text/html; charset=utf-8', headers = {} } = {}
) {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      ...headers,
    },
  });
}

function makeDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

function makeHarness({
  environment = makeEnvironment(),
  responseFactory = () => makeResponse(makeHtml('version-1', environment.CALENDAR_URL)),
} = {}) {
  const cache = new MemoryCache();
  const context = makeContext();
  const calls = [];
  const runtime = {
    cache,
    fetch: async (target, init) => {
      calls.push({ target: String(target), init });
      return await responseFactory({ target: String(target), init, calls });
    },
  };
  return {
    cache,
    calls,
    context,
    environment,
    worker: loadWorker(runtime),
  };
}

test('sanitized calendar page misses populate an opaque final-view cache', async () => {
  const cache = new MemoryCache();
  const context = makeContext();
  const environment = makeEnvironment();
  const sourceUrl = environment.CALENDAR_URL;

  const worker = loadWorker({
    cache,
    fetch: async () =>
      new Response('<html><head></head><body>calendar ' + sourceUrl + '</body></html>', {
        status: 200,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          etag: 'upstream-etag',
          'set-cookie': 'source-cookie=secret',
        },
      }),
  });

  const response = await worker.fetch(
    new Request('https://calendar.example.test/calendar.html?skin=light&tab=week'),
    environment,
    context
  );
  const body = await response.text();
  await context.flush();

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.ok(!body.includes(sourceUrl));
  assert.equal(cache.putCalls.length, 1);

  const [storedKey] = cache.entries.keys();
  assert.match(storedKey, /^https:\/\/calendar-final-view\.invalid\/v1\/[0-9a-f]+$/);
  assert.ok(!storedKey.includes(sourceUrl));
  assert.ok(!storedKey.includes(environment.CACHE_IDENTITY_SECRET));
  assert.equal(cache.putCalls[0].response.headers.get('set-cookie'), null);
  assert.equal(cache.putCalls[0].response.headers.get('etag'), null);
});

test('configured encryption and filtering secrets never reach final representations', async () => {
  const environment = {
    ...makeEnvironment(),
    ENCRYPTION_KEY: 'encryption-material-that-must-stay-private',
    USER_EMAILS: 'owner@example.test,second-owner@example.test',
  };
  const sensitiveBody = [
    environment.CALENDAR_URL,
    environment.ENCRYPTION_KEY,
    environment.USER_EMAILS,
  ].join(' ');
  const harness = makeHarness({
    environment,
    responseFactory: () => makeResponse('<html><body>' + sensitiveBody + '</body></html>'),
  });

  const response = await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html?skin=light'),
    environment,
    harness.context
  );
  const body = await response.text();
  await harness.context.flush();
  const cachedBody = await harness.cache.entries.values().next().value.clone().text();

  for (const value of [
    environment.CALENDAR_URL,
    environment.ENCRYPTION_KEY,
    environment.USER_EMAILS,
    'owner@example.test',
    'second-owner@example.test',
  ]) {
    assert.ok(!body.includes(value), value);
    assert.ok(!cachedBody.includes(value), value);
  }
});

test('final-view cache identities hide sources and separate every safe variant', async () => {
  const environment = makeEnvironment();
  let version = 0;
  const harness = makeHarness({
    environment,
    responseFactory: () => makeResponse(makeHtml('version-' + ++version, environment.CALENDAR_URL)),
  });

  const baseUrl = 'https://calendar.example.test/calendar.html?skin=light&tab=week&date=2026-09-07';
  await harness.worker.fetch(new Request(baseUrl), environment, harness.context);
  await harness.context.flush();

  const reorderedWithViewerUrl =
    'https://calendar.example.test/calendar.html?date=2026-09-07&tab=week&skin=light' +
    '&URL=https%3A%2F%2Fattacker.example%2Fcalendar.ics';
  const reorderedResponse = await harness.worker.fetch(
    new Request(reorderedWithViewerUrl),
    environment,
    harness.context
  );
  assert.match(await reorderedResponse.text(), /version-1/);
  assert.equal(version, 1);
  assert.equal(harness.cache.entries.size, 1);

  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html?skin=dark&tab=week&date=2026-09-07'),
    environment,
    harness.context
  );
  await harness.context.flush();
  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html?skin=light&tab=month&date=2026-09-07'),
    environment,
    harness.context
  );
  await harness.context.flush();
  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html?skin=light&tab=week&date=2026-09-08'),
    environment,
    harness.context
  );
  await harness.context.flush();
  assert.equal(harness.cache.entries.size, 4);

  const rotatedEnvironment = {
    ...environment,
    CALENDAR_URL: 'https://calendar.example.test/rotated.ics',
  };
  await harness.worker.fetch(new Request(baseUrl), rotatedEnvironment, harness.context);
  await harness.context.flush();
  const changedEncryptionEnvironment = {
    ...environment,
    ENCRYPTION_KEY: 'rotated-encryption-material',
  };
  await harness.worker.fetch(new Request(baseUrl), changedEncryptionEnvironment, harness.context);
  await harness.context.flush();
  const changedEmailEnvironment = {
    ...environment,
    USER_EMAILS: 'different-owner@example.test',
  };
  await harness.worker.fetch(new Request(baseUrl), changedEmailEnvironment, harness.context);
  await harness.context.flush();
  assert.equal(harness.cache.entries.size, 7);

  for (const key of harness.cache.entries.keys()) {
    assert.match(key, /^https:\/\/calendar-final-view\.invalid\/v1\/[0-9a-f]+$/);
    assert.ok(!key.includes('calendar.example.test'));
    assert.ok(!key.includes('attacker.example'));
    assert.ok(!key.includes('rotated-encryption-material'));
  }
});

test('unknown viewer query keys do not create final-view cache variants', async () => {
  const environment = makeEnvironment();
  const harness = makeHarness({ environment });
  const baseUrl = 'https://calendar.example.test/calendar.html?skin=light&tab=week&ignored=first';

  await harness.worker.fetch(new Request(baseUrl), environment, harness.context);
  await harness.context.flush();
  const response = await harness.worker.fetch(
    new Request(baseUrl.replace('ignored=first', 'ignored=second')),
    environment,
    harness.context
  );

  assert.equal(response.status, 200);
  assert.equal(harness.calls.length, 1);
  assert.equal(harness.cache.entries.size, 1);
});

test('calendar event range parameters are forwarded and preserve duplicate order', async () => {
  const environment = makeEnvironment();
  const harness = makeHarness({
    environment,
    responseFactory: () =>
      makeResponse('{"events":[]}', { contentType: 'application/json; charset=utf-8' }),
  });
  const firstUrl =
    'https://calendar.example.test/calendar.events.json' +
    '?to=2026-09-08T00%3A00%3A00Z&from=first&from=second&timezone=UTC&ignored=one';

  await harness.worker.fetch(new Request(firstUrl), environment, harness.context);
  await harness.context.flush();

  const forwardedUrl = new URL(harness.calls[0].target);
  assert.deepEqual(forwardedUrl.searchParams.getAll('from'), ['first', 'second']);
  assert.equal(forwardedUrl.searchParams.get('to'), '2026-09-08T00:00:00Z');
  assert.equal(forwardedUrl.searchParams.get('timezone'), 'UTC');
  assert.equal(forwardedUrl.searchParams.get('ignored'), null);

  await harness.worker.fetch(
    new Request(
      firstUrl.replace(
        'to=2026-09-08T00%3A00%3A00Z&from=first&from=second&timezone=UTC&ignored=one',
        'timezone=UTC&from=first&from=second&to=2026-09-08T00%3A00%3A00Z&ignored=two'
      )
    ),
    environment,
    harness.context
  );
  assert.equal(harness.calls.length, 1);

  await harness.worker.fetch(
    new Request(firstUrl.replace('from=first&from=second', 'from=second&from=first')),
    environment,
    harness.context
  );
  assert.equal(harness.calls.length, 2);
  await harness.context.flush();
  assert.equal(harness.cache.entries.size, 2);
});

test('fresh hits stay fast while stale hits refresh and auto-revalidate in the calendar frame', async () => {
  const environment = makeEnvironment();
  let version = 1;
  const harness = makeHarness({
    environment,
    responseFactory: () => makeResponse(makeHtml('version-' + version, environment.CALENDAR_URL)),
  });
  const calendarUrl = 'https://calendar.example.test/calendar.html?skin=light&tab=week';

  const firstResponse = await harness.worker.fetch(
    new Request(calendarUrl),
    environment,
    harness.context
  );
  assert.match(await firstResponse.text(), /version-1/);
  await harness.context.flush();

  const freshResponse = await harness.worker.fetch(
    new Request(calendarUrl),
    environment,
    harness.context
  );
  assert.match(await freshResponse.text(), /version-1/);
  assert.equal(harness.calls.length, 1);
  await harness.context.flush();
  assert.equal(harness.calls.length, 1);

  await harness.cache.markStale();
  version = 2;
  const staleResponse = await harness.worker.fetch(
    new Request(calendarUrl),
    environment,
    harness.context
  );
  const staleBody = await staleResponse.text();
  assert.match(staleBody, /version-1/);
  assert.match(staleBody, /calendar-cache-stale/);
  await harness.context.flush();
  assert.equal(harness.calls.length, 2);
  const refreshedEntry = harness.cache.entries.values().next().value;
  assert.match(await refreshedEntry.clone().text(), /version-2/);

  await harness.cache.markStale();
  version = 3;
  const automaticResponse = await harness.worker.fetch(
    new Request(calendarUrl + '&__cal_revalidate=1'),
    environment,
    harness.context
  );
  const automaticBody = await automaticResponse.text();
  assert.match(automaticBody, /version-3/);
  assert.doesNotMatch(automaticBody, /__cal_revalidate/);
  await harness.context.flush();
  assert.match(await harness.cache.entries.values().next().value.clone().text(), /version-3/);
});

test('explicit revalidation refreshes a fresh entry and reports its result', async () => {
  const environment = makeEnvironment();
  let version = 1;
  const harness = makeHarness({
    environment,
    responseFactory: () => makeResponse(makeHtml('version-' + version, environment.CALENDAR_URL)),
  });
  const calendarUrl = 'https://calendar.example.test/calendar.html?skin=light&tab=week';

  await harness.worker.fetch(new Request(calendarUrl), environment, harness.context);
  await harness.context.flush();
  version = 2;

  const response = await harness.worker.fetch(
    new Request(calendarUrl + '&__cal_revalidate=1'),
    environment,
    harness.context
  );

  assert.equal(response.headers.get('x-calendar-view-status'), 'updated');
  assert.match(await response.text(), /version-2/);
  assert.equal(harness.calls.length, 2);
  await harness.context.flush();
  assert.match(await harness.cache.entries.values().next().value.clone().text(), /version-2/);
});

test('explicit revalidation is cooled down per final-view cache key', async () => {
  const environment = makeEnvironment();
  let version = 1;
  const harness = makeHarness({
    environment,
    responseFactory: () => makeResponse(makeHtml('version-' + version, environment.CALENDAR_URL)),
  });
  const calendarUrl = 'https://calendar.example.test/calendar.html?skin=light&tab=week';

  await harness.worker.fetch(new Request(calendarUrl), environment, harness.context);
  await harness.context.flush();
  version = 2;
  const updatedResponse = await harness.worker.fetch(
    new Request(calendarUrl + '&__cal_revalidate=1'),
    environment,
    harness.context
  );
  assert.equal(updatedResponse.headers.get('x-calendar-view-status'), 'updated');
  assert.match(await updatedResponse.text(), /version-2/);
  assert.equal(harness.calls.length, 2);

  version = 3;
  const throttledResponse = await harness.worker.fetch(
    new Request(calendarUrl + '&__cal_revalidate=1'),
    environment,
    harness.context
  );
  assert.equal(throttledResponse.headers.get('x-calendar-view-status'), 'fresh');
  assert.match(await throttledResponse.text(), /version-2/);
  assert.equal(harness.calls.length, 2);
});

test('concurrent stale requests share one in-flight refresh', async () => {
  const environment = makeEnvironment();
  let upstreamCalls = 0;
  const refresh = makeDeferred();
  const harness = makeHarness({
    environment,
    responseFactory: () => {
      upstreamCalls += 1;
      if (upstreamCalls === 1) {
        return makeResponse(makeHtml('version-1', environment.CALENDAR_URL));
      }
      return refresh.promise;
    },
  });
  const calendarUrl = 'https://calendar.example.test/calendar.html?skin=light&tab=week';

  await harness.worker.fetch(new Request(calendarUrl), environment, harness.context);
  await harness.context.flush();
  await harness.cache.markStale();

  const staleResponses = await Promise.all([
    harness.worker.fetch(new Request(calendarUrl), environment, harness.context),
    harness.worker.fetch(new Request(calendarUrl), environment, harness.context),
  ]);
  assert.equal(upstreamCalls, 2);
  assert.match(await staleResponses[0].text(), /version-1/);
  assert.match(await staleResponses[1].text(), /version-1/);

  refresh.resolve(makeResponse(makeHtml('version-2', environment.CALENDAR_URL)));
  await harness.context.flush();
  assert.match(await harness.cache.entries.values().next().value.clone().text(), /version-2/);
});

test('failed stale refreshes preserve the last-known-good representation', async () => {
  const environment = makeEnvironment();
  let shouldFail = false;
  const harness = makeHarness({
    environment,
    responseFactory: () => {
      if (shouldFail) {
        return makeResponse('upstream unavailable', {
          status: 503,
          contentType: 'text/html; charset=utf-8',
        });
      }
      return makeResponse(makeHtml('last-good', environment.CALENDAR_URL));
    },
  });
  const calendarUrl = 'https://calendar.example.test/calendar.html?skin=dark&tab=week';

  await harness.worker.fetch(new Request(calendarUrl), environment, harness.context);
  await harness.context.flush();
  await harness.cache.markStale();
  shouldFail = true;
  const staleResponse = await harness.worker.fetch(
    new Request(calendarUrl),
    environment,
    harness.context
  );
  assert.match(await staleResponse.text(), /last-good/);
  await harness.context.flush();
  assert.match(await harness.cache.entries.values().next().value.clone().text(), /last-good/);
  assert.equal(harness.cache.putCalls.length, 1);
});

test('failed explicit revalidation keeps the stale view and signals no replacement', async () => {
  const environment = makeEnvironment();
  let shouldFail = false;
  const harness = makeHarness({
    environment,
    responseFactory: () => {
      if (shouldFail) {
        return makeResponse('temporary failure', { status: 503 });
      }
      return makeResponse(makeHtml('last-good', environment.CALENDAR_URL));
    },
  });
  const calendarUrl = 'https://calendar.example.test/calendar.html?skin=light';

  await harness.worker.fetch(new Request(calendarUrl), environment, harness.context);
  await harness.context.flush();
  shouldFail = true;
  const response = await harness.worker.fetch(
    new Request(calendarUrl + '&__cal_revalidate=1'),
    environment,
    harness.context
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-calendar-view-status'), 'stale');
  assert.match(await response.text(), /last-good/);
  assert.equal(harness.cache.putCalls.length, 1);
});

test('only explicit final page and calendar-data responses enter the cache', async () => {
  const environment = makeEnvironment();
  const harness = makeHarness({
    environment,
    responseFactory: ({ target }) => {
      const targetPath = new URL(target).pathname;
      if (targetPath === '/calendar.json') {
        return makeResponse(
          JSON.stringify({
            name: 'Private calendar',
            metadata: environment.CALENDAR_URL,
            events: [],
          }),
          { contentType: 'application/json; charset=utf-8' }
        );
      }
      if (targetPath === '/asset.json') {
        return makeResponse('{"name":"static data","value":true}', {
          contentType: 'application/json; charset=utf-8',
        });
      }
      if (targetPath === '/calendar.js') {
        return makeResponse('console.log("static");', {
          contentType: 'application/javascript',
        });
      }
      return makeResponse(makeHtml('page', environment.CALENDAR_URL));
    },
  });

  const pageResponse = await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html?skin=light'),
    environment,
    harness.context
  );
  assert.match(await pageResponse.text(), /page/);
  await harness.context.flush();
  assert.equal(harness.cache.putCalls.length, 1);

  const dataResponse = await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.json?skin=light'),
    environment,
    harness.context
  );
  const dataBody = await dataResponse.text();
  assert.doesNotMatch(dataBody, /Private calendar/);
  assert.ok(!dataBody.includes(environment.CALENDAR_URL));
  await harness.context.flush();
  assert.equal(harness.cache.putCalls.length, 2);

  await harness.worker.fetch(
    new Request('https://calendar.example.test/asset.json'),
    environment,
    harness.context
  );
  await harness.context.flush();
  assert.equal(harness.cache.putCalls.length, 2);

  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.js'),
    environment,
    harness.context
  );
  await harness.context.flush();
  assert.equal(harness.cache.putCalls.length, 2);

  const blocked = await harness.worker.fetch(
    new Request('https://calendar.example.test/private.ICS'),
    environment,
    harness.context
  );
  assert.equal(blocked.status, 403);
  assert.equal(harness.cache.putCalls.length, 2);
});

test('cache entries and viewer responses use a safe header allowlist', async () => {
  const environment = makeEnvironment();
  const harness = makeHarness({
    environment,
    responseFactory: () =>
      makeResponse(makeHtml('headers', environment.CALENDAR_URL), {
        headers: {
          etag: 'upstream-etag',
          'last-modified': 'yesterday',
          'set-cookie': 'source-cookie=secret',
          location: 'https://source.example.test/private',
          'content-encoding': 'gzip',
          'content-length': '123',
          'x-source-location': environment.CALENDAR_URL,
        },
      }),
  });

  const response = await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html'),
    environment,
    harness.context
  );
  await response.text();
  await harness.context.flush();

  for (const header of [
    'etag',
    'last-modified',
    'set-cookie',
    'location',
    'content-encoding',
    'content-length',
    'x-source-location',
  ]) {
    assert.equal(response.headers.get(header), null, header);
    assert.equal(harness.cache.putCalls[0].response.headers.get(header), null, header);
  }
  assert.equal(response.headers.get('x-calendar-cache-stored-at'), null);
  assert.match(
    harness.cache.putCalls[0].response.headers.get('x-calendar-cache-stored-at'),
    /^[0-9]+$/
  );
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(
    harness.cache.putCalls[0].response.headers.get('cache-control'),
    'public, max-age=86400'
  );
});

test('missing identity secret, credentials, and non-GET requests bypass shared caching', async () => {
  const environment = makeEnvironment();
  const harness = makeHarness({
    environment,
    responseFactory: ({ init }) => {
      assert.equal(init.cache, 'no-store');
      assert.equal(init.headers.get('cookie'), null);
      assert.equal(init.headers.get('authorization'), null);
      return makeResponse(makeHtml('live', environment.CALENDAR_URL));
    },
  });

  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html', {
      headers: { Cookie: 'viewer=session', Authorization: 'Bearer viewer' },
    }),
    environment,
    harness.context
  );
  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    environment,
    harness.context
  );
  const noSecretEnvironment = {
    ...environment,
    CACHE_IDENTITY_SECRET: '',
  };
  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html'),
    noSecretEnvironment,
    harness.context
  );
  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html?__cal_revalidate=1'),
    noSecretEnvironment,
    harness.context
  );
  await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html'),
    noSecretEnvironment,
    harness.context
  );
  const bypassEnvironment = {
    ...environment,
    CACHE_BYPASS: '1',
  };
  await harness.worker.fetch(
    new Request(
      'https://calendar.example.test/calendar.html?url=https%3A%2F%2Fattacker.test%2Fevil.ics'
    ),
    bypassEnvironment,
    harness.context
  );
  await harness.worker.fetch(
    new Request(
      'https://calendar.example.test/calendar.html?url=https%3A%2F%2Fattacker.test%2Fevil.ics'
    ),
    bypassEnvironment,
    harness.context
  );
  await harness.context.flush();

  assert.equal(harness.calls.length, 7);
  assert.equal(harness.cache.putCalls.length, 0);
  assert.equal(harness.cache.matchCalls.length, 0);
  assert.ok(harness.calls.every(call => !call.target.includes('attacker.test')));
});

test('empty, malformed, and error-only JSON responses are not cached', async () => {
  const environment = makeEnvironment();
  let body = '';
  const harness = makeHarness({
    environment,
    responseFactory: ({ target }) => {
      const targetUrl = new URL(target);
      if (targetUrl.pathname === '/calendar.json') {
        return makeResponse(body, { contentType: 'application/json; charset=utf-8' });
      }
      return makeResponse(makeHtml('page', environment.CALENDAR_URL));
    },
  });
  const cases = ['', '{not-json', '{"error":"upstream unavailable"}'];

  for (const [index, candidate] of cases.entries()) {
    body = candidate;
    const response = await harness.worker.fetch(
      new Request('https://calendar.example.test/calendar.json?tab=week&case=' + index),
      environment,
      harness.context
    );
    assert.equal(response.status, 200);
    await response.arrayBuffer();
    await harness.context.flush();
  }

  assert.equal(harness.cache.putCalls.length, 0);
});

test('JSONP-looking content is not treated as calendar JSON', async () => {
  const environment = makeEnvironment();
  const harness = makeHarness({
    environment,
    responseFactory: () =>
      makeResponse('{"events":[]}', { contentType: 'application/jsonp; charset=utf-8' }),
  });

  const response = await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.json'),
    environment,
    harness.context
  );
  assert.equal(response.status, 200);
  await response.arrayBuffer();
  await harness.context.flush();
  assert.equal(harness.cache.putCalls.length, 0);
});

test('empty calendar configuration fails closed without touching the cache', async () => {
  const environment = {
    ...makeEnvironment(),
    CALENDAR_URL: '   ',
  };
  const harness = makeHarness({ environment });

  const response = await harness.worker.fetch(
    new Request('https://calendar.example.test/calendar.html'),
    environment,
    harness.context
  );

  assert.equal(response.status, 500);
  assert.doesNotMatch(await response.text(), /calendar\.example\.test/);
  assert.equal(harness.calls.length, 0);
  assert.equal(harness.cache.matchCalls.length, 0);
  assert.equal(harness.cache.putCalls.length, 0);
});

test('the parent template revalidates page and data before reloading a stale iframe', () => {
  const template = fs.readFileSync(path.join(__dirname, '..', 'index.html.template'), 'utf8');
  const worker = fs.readFileSync(path.join(__dirname, '..', 'worker.js'), 'utf8');

  assert.match(worker, /postMessage\(\{\s*type:\s*['"]calendar-cache-stale['"]/);
  assert.match(template, /event\.data\.type\s*!==\s*['"]calendar-cache-stale['"]/);
  assert.match(template, /credentials:\s*['"]omit['"]/);
  assert.match(template, /calendar\.json/);
  assert.match(template, /__cal_revalidate/);
  assert.match(template, /X-Calendar-View-Status/);
  assert.match(template, /iframe\.src\s*!==\s*pageUrl\.toString\(\)/);
});

test('malformed and non-success cache candidates are never served or stored', async () => {
  const environment = makeEnvironment();
  let responseMode = 'good';
  const harness = makeHarness({
    environment,
    responseFactory: () => {
      if (responseMode === 'error') {
        return makeResponse('not available', {
          status: 503,
          contentType: 'text/html; charset=utf-8',
        });
      }
      return makeResponse(makeHtml('good', environment.CALENDAR_URL));
    },
  });
  const calendarUrl = 'https://calendar.example.test/calendar.html?skin=dark';

  await harness.worker.fetch(new Request(calendarUrl), environment, harness.context);
  await harness.context.flush();
  const [key, entry] = harness.cache.entries.entries().next().value;
  const malformedHeaders = new Headers(entry.headers);
  malformedHeaders.delete('x-calendar-cache-stored-at');
  harness.cache.entries.set(
    key,
    new Response(await entry.clone().arrayBuffer(), {
      status: entry.status,
      headers: malformedHeaders,
    })
  );
  responseMode = 'error';
  const response = await harness.worker.fetch(
    new Request(calendarUrl),
    environment,
    harness.context
  );
  assert.equal(response.status, 503);
  await harness.context.flush();
  assert.equal(harness.cache.putCalls.length, 1);
});
