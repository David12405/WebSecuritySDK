// Deliberately vulnerable static-analysis fixture. This file is never deployed or executed.
export async function vulnerableFixture(request, env, childProcess) {
  const url = new URL(request.url);

  eval(url.searchParams.get("expression"));

  await env.DB.prepare(url.searchParams.get("unsafe_sql")).all();

  childProcess.exec(url.searchParams.get("command"));
}
