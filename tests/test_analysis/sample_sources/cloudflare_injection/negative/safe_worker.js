// Negative control: request data never controls code, SQL text, or a command.
export async function safeFixture(request, env, childProcess) {
  const url = new URL(request.url);
  const userId = url.searchParams.get("user_id");
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first();
  childProcess.exec("/usr/bin/true");
  return Response.json(user);
}
