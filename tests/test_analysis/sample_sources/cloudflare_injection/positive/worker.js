// Deliberately vulnerable static-analysis fixture. Never deployed or executed.
export async function vulnerableFixture(request, env, childProcess) {
  const url = new URL(request.url);
  const expression = url.searchParams.get("expression");
  eval(expression);

  const body = await request.json();
  await env.DB.prepare(body.unsafeSql).all();

  const form = await request.formData();
  childProcess.exec(form.get("command"));
}
