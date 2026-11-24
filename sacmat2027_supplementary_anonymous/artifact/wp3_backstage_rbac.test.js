/*
 * WP3 -- Layered conformance probes for the Backstage RBAC backend
 * (@backstage-community/plugin-rbac-backend 8.1.6, released package, unmodified).
 *
 * The real permission backend + RBAC plugin run in Backstage's own test backend
 * (startTestBackend, SQLite). A small fake catalog plugin serves the two catalog
 * queries the RBAC role manager issues, from a mutable in-memory store, so that group
 * membership can be changed at run time.
 *
 * B1 (L1)  bounded differential: /api/permission/authorize vs the documented semantics
 *          (named-permission policies take priority over resource-type policies; within the
 *          chosen kind, deny overrides allow; no policy -> deny), over 3^4 = 81 policy
 *          configurations for a user holding one role directly and one through a group.
 * B2 (L2)  freshness of group membership: catalog removal, role-membership removal, and the
 *          `useOwnershipEntityRefs` mode in which group refs come from the user's token claims.
 * Results are written to results.json.
 */
const fs = require('fs');
const request = require('supertest');
const { createServiceFactory, coreServices, createBackendPlugin } = require('@backstage/backend-plugin-api');
const { mockCredentials, mockServices, startTestBackend } = require('@backstage/backend-test-utils');
const permissionBackend = require('@backstage/plugin-permission-backend').default;
const rbac = require('@backstage-community/plugin-rbac-backend');
const rbacPlugin = rbac.rbacPlugin ?? rbac.default;
const express = require('express');

jest.setTimeout(600_000);
const OUT = {};

// ---- token-claim stand-in: ownership refs per user, as issued at sign-in -----------
const CLAIMS = {};

// ---- mutable fake catalog -----------------------------------------------------------
const CATALOG = { groups: { 'team-a': ['alice'] }, users: ['admin', 'alice', 'bob'] };
function entities() {
  const out = [];
  for (const u of CATALOG.users) {
    out.push({ apiVersion: 'backstage.io/v1alpha1', kind: 'User', metadata: { name: u, namespace: 'default' },
      spec: { memberOf: Object.entries(CATALOG.groups).filter(([, m]) => m.includes(u)).map(([g]) => g) } });
  }
  for (const [g, m] of Object.entries(CATALOG.groups)) {
    out.push({ apiVersion: 'backstage.io/v1alpha1', kind: 'Group', metadata: { name: g, namespace: 'default' },
      spec: { type: 'team', children: [], members: m },
      relations: m.map(u => ({ type: 'hasMember', targetRef: `user:default/${u}` })) });
  }
  return out;
}
function matches(e, filters) {
  return filters.every(([k, v]) => {
    if (k === 'kind') return e.kind.toLowerCase() === v.toLowerCase();
    if (k === 'relations.hasmember') return (e.relations || []).some(r => r.type === 'hasMember' && r.targetRef === v.toLowerCase());
    return true;
  });
}
const fakeCatalog = createBackendPlugin({
  pluginId: 'catalog',
  register(env) {
    env.registerInit({
      deps: { http: coreServices.httpRouter },
      async init({ http }) {
        const r = express.Router();
        r.get('/entities', (req, res) => {
          const raw = [].concat(req.query.filter || []);
          const filters = raw.flatMap(f => String(f).split(',')).map(p => {
            const i = p.indexOf('='); return [p.slice(0, i).toLowerCase(), p.slice(i + 1)];
          });
          OUT._catalog_queries = (OUT._catalog_queries || 0) + 1;
          res.json(entities().filter(e => matches(e, filters)));
        });
        http.use(r);
        http.addAuthPolicy({ path: '/', allow: 'unauthenticated' });
      },
    });
  },
});

// ---- user-info service whose ownership refs model token claims ----------------------
const userInfoFactory = createServiceFactory({
  service: coreServices.userInfo,
  deps: {},
  factory: () => ({
    async getUserInfo(credentials) {
      const ref = credentials.principal.userEntityRef;
      return { userEntityRef: ref, ownershipEntityRefs: CLAIMS[ref] ?? [ref] };
    },
  }),
});

// mock OBO flow drops the actor (same workaround as the plugin's own tests)
const origUser = mockCredentials.user;
const userCred = ref => origUser(ref, { actor: { subject: 'plugin:permission' } });
Object.assign(userCred, origUser);
mockCredentials.user = userCred;

async function start(extraRbac = {}) {
  return startTestBackend({
    features: [
      permissionBackend, rbacPlugin, fakeCatalog, userInfoFactory,
      mockServices.rootConfig.factory({ data: {
        backend: { database: { client: 'better-sqlite3', connection: ':memory:' } },
        permission: { enabled: true, rbac: { admin: { users: [{ name: 'user:default/admin' }] }, ...extraRbac } },
      } }),
      mockServices.httpAuth.factory({ defaultCredentials: mockCredentials.service() }),
    ],
  });
}
const H = ref => ({ Authorization: mockCredentials.user.header(ref) });
const ADMIN = H('user:default/admin');
const PERM = { type: 'resource', name: 'catalog.entity.read', attributes: { action: 'read' }, resourceType: 'catalog-entity' };

async function authorize(server, user) {
  const r = await request(server).post('/api/permission/authorize').set(H(user))
    .send({ items: [{ id: '1', permission: PERM }] });
  if (r.status !== 200) return `HTTP${r.status}`;
  return r.body.items[0].result;
}
async function setRole(server, name, members, policies) {
  await request(server).delete(`/api/permission/roles/role/default/${name}`).set(ADMIN);
  const c = await request(server).post('/api/permission/roles').set(ADMIN)
    .send({ name: `role:default/${name}`, memberReferences: members });
  if (policies.length) {
    const p = await request(server).post('/api/permission/policies').set(ADMIN)
      .send(policies.map(([perm, effect]) => ({ entityReference: `role:default/${name}`, permission: perm, policy: 'read', effect })));
    return [c.status, p.status];
  }
  return [c.status, null];
}

function documented(cfg) {
  // cfg: [[named, type] for R1, [named, type] for R2], each in {null, 'allow', 'deny'}
  const named = cfg.map(c => c[0]).filter(Boolean), type = cfg.map(c => c[1]).filter(Boolean);
  const pick = named.length ? named : type;
  if (!pick.length) return 'DENY';
  return pick.includes('allow') && !pick.includes('deny') ? 'ALLOW' : 'DENY';
}

afterAll(() => fs.writeFileSync('results.json', JSON.stringify(OUT, null, 1)));

test('B1 L1 bounded differential vs documented semantics', async () => {
  const V = [null, 'allow', 'deny'];
  let n = 0, agree = 0; const mism = []; const http = {};
  for (const a of V) for (const b of V) for (const c of V) for (const d of V) {
    const backend = await start();            // fresh store per configuration
    const cfg = [[a, b], [c, d]];
    const pol = cfg.map(([nm, ty]) => [nm && ['catalog.entity.read', nm], ty && ['catalog-entity', ty]].filter(Boolean));
    const s1 = await setRole(backend.server, 'r1', ['user:default/alice'], pol[0]);
    const s2 = await setRole(backend.server, 'r2', ['group:default/team-a'], pol[1]);
    http[JSON.stringify([s1, s2])] = (http[JSON.stringify([s1, s2])] || 0) + 1;
    const got = await authorize(backend.server, 'user:default/alice');
    const exp = documented(cfg);
    n++; if (got === exp) agree++; else if (mism.length < 10) mism.push({ cfg, expected: exp, got });
    await backend.stop();
  }
  OUT.B1 = { configurations: n, agree, mismatches: mism, setup_http_status_histogram: http };
});

test('B2 L2 freshness of membership', async () => {
  const res = {};
  // (a) catalog membership removed
  let backend = await start();
  CATALOG.groups['team-a'] = ['alice'];
  await setRole(backend.server, 'r2', ['group:default/team-a'], [['catalog-entity', 'allow']]);
  res.catalog_before = await authorize(backend.server, 'user:default/alice');
  CATALOG.groups['team-a'] = [];
  res.catalog_after_removal_next_decision = await authorize(backend.server, 'user:default/alice');
  // (b) role membership removed through the REST API
  CATALOG.groups['team-a'] = ['alice'];
  await setRole(backend.server, 'r3', ['user:default/bob'], [['catalog-entity', 'allow']]);
  res.role_before = await authorize(backend.server, 'user:default/bob');
  const put = await request(backend.server).put('/api/permission/roles/role/default/r3').set(ADMIN)
    .send({ oldRole: { name: 'role:default/r3', memberReferences: ['user:default/bob'] },
            newRole: { name: 'role:default/r3', memberReferences: ['user:default/admin'] } });
  res.role_update_http = put.status;
  res.role_after_removal_next_decision = await authorize(backend.server, 'user:default/bob');
  await backend.stop();
  // (c) useOwnershipEntityRefs: group refs taken from token claims issued at sign-in
  backend = await start({ useOwnershipEntityRefs: true });
  CATALOG.groups['team-a'] = ['alice'];
  CLAIMS['user:default/alice'] = ['user:default/alice', 'group:default/team-a'];
  await setRole(backend.server, 'r2', ['group:default/team-a'], [['catalog-entity', 'allow']]);
  res.claims_before = await authorize(backend.server, 'user:default/alice');
  CATALOG.groups['team-a'] = [];               // membership revoked in the catalog ...
  res.claims_after_catalog_removal_token_unchanged = await authorize(backend.server, 'user:default/alice');
  CLAIMS['user:default/alice'] = ['user:default/alice'];   // ... until a new token is issued
  res.claims_after_token_reissue = await authorize(backend.server, 'user:default/alice');
  await backend.stop();
  OUT.B2 = res;
});
