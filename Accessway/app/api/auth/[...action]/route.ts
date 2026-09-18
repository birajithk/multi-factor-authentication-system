import { env } from "cloudflare:workers";
import { handleAuth, type AuthEnvironment } from "@/lib/auth-service";

export const dynamic = "force-dynamic";
export const GET = (request: Request) => handleAuth(request, env as unknown as AuthEnvironment);
export const POST = (request: Request) => handleAuth(request, env as unknown as AuthEnvironment);
