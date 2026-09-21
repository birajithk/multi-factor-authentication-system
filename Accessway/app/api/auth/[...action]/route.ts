import { env } from "cloudflare:workers";
import { handleAuth, type AuthEnvironment } from "@/lib/auth-service";

export const dynamic = "force-dynamic";

// If the worker env is not populated (local dev), return a safe demo response
// for the `status` route so the UI can continue without the full dispatcher.
export const GET = (request: Request) => {
	try {
		const hasEnv = Boolean((env as any).DB || (env as any).APP_ORIGIN || (env as any).MFA_ENCRYPTION_KEY);
		const url = new URL(request.url);
		if (!hasEnv && url.pathname.endsWith("/api/auth/status")) {
			const demo = { configured: false, hasPassword: false, email: "seedy@sites.test", phase: "password", hasTotp: false, hasKey: false };
			return new Response(JSON.stringify(demo), { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } });
		}
	} catch {
		// fall through to handler
	}
	return handleAuth(request, env as unknown as AuthEnvironment);
};

export const POST = (request: Request) => handleAuth(request, env as unknown as AuthEnvironment);
