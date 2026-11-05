// Deliberately vulnerable static-analysis fixture. This file is never deployed or executed.
export async function vulnerableFixture(request, env, childProcess) {
  const url = new URL(request.url);

  const expression = url.searchParams.get("expression");
  eval(expression);

  const userId = url.searchParams.get("user_id");
  await env.DB.prepare(`SELECT * FROM users WHERE id = ${userId}`).all();

  const command = url.searchParams.get("command");
  childProcess.exec(command);
}
