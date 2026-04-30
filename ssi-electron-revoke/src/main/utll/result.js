function ok(data) {
  return { ok: true, data };
}

function fail(error) {
  return { ok: false, error };
}

module.exports = { ok, fail };
