"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { createClient } from "@/src/lib/supabase/client";
import { Loader2, Eye, EyeOff, Shield, ShieldCheck, Lock, ArrowRight } from "lucide-react";

const GithubIcon = (props: React.SVGProps<SVGSVGElement>) => (
  <svg
    {...props}
    viewBox="0 0 24 24"
    fill="currentColor"
    xmlns="http://www.w3.org/2000/svg"
  >
    <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
  </svg>
);

const quotes = [
  {
    text: "SBOM.io has completely transformed how we handle compliance. What used to take weeks of manual work now happens in minutes with 100% accuracy.",
    author: "Sarah Chen",
    role: "Head of Security, FinTech Global",
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Sarah",
  },
  {
    text: "The proactive vulnerability alerts are a literal lifesaver. We identified and patched a critical transitive dependency issue before it even hit production.",
    author: "Marcus Thorne",
    role: "DevOps Architect, CloudScale",
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Marcus",
  },
  {
    text: "Finally, an SBOM tool that actually understands the complexities of modern enterprise software. The CycloneDX exports are flawless.",
    author: "Elena Rodriguez",
    role: "CTO, SecureStack",
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Elena",
  },
];

export default function LoginPage() {
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState<"github" | "email" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // FIX 1: quoteIndex must start at 0 and ONLY update after mount.
  // Previously the interval started immediately and could fire during hydration,
  // causing the left-panel height to change mid-render and push the right panel down.
  const [quoteIndex, setQuoteIndex] = useState(0);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const interval = setInterval(() => {
      setQuoteIndex((prev) => (prev + 1) % quotes.length);
    }, 8000);
    return () => clearInterval(interval);
  }, []);

  function getCallbackUrl() {
    const nextPath =
      new URLSearchParams(window.location.search).get("next") ??
      "/dashboard";

    return `${
      window.location.origin
    }/auth/callback?next=${encodeURIComponent(nextPath)}`;
  }

  async function signInWithGitHub() {
    setLoading("github");
    setError(null);
    setMessage(null);

    const supabase = createClient();
    const { error: authError } = await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo: getCallbackUrl(),
      },
    });

    if (authError) {
      setError(authError.message);
      setLoading(null);
    }
  }

  async function handleEmailAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading("email");
    setError(null);
    setMessage(null);

    const supabase = createClient();

    if (isSignUp) {
      const { error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: getCallbackUrl(),
        },
      });

      if (authError) {
        setError(authError.message);
      } else {
        setMessage(
          "Registration successful! Please check your email to verify your account."
        );
      }
    } else {
      const { error: authError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (authError) {
        setError(authError.message);
      } else {
        window.location.href =
          new URLSearchParams(window.location.search).get("next") ??
          "/dashboard";
      }
    }

    setLoading(null);
  }

  return (
    <div className="min-h-screen w-full bg-black text-white selection:bg-[#10b981]/30 font-sans flex overflow-hidden">

      {/* --- LEFT PANEL: BRANDING & TRUST --- */}
      <div className="hidden lg:flex relative w-1/2 flex-shrink-0 flex-col p-12 border-r border-white/5 bg-[#050505] overflow-hidden">

        {/* Background Decorative Elements */}
        <div className="absolute top-0 left-0 w-full h-full">
          <div className="absolute top-[-10%] left-[-10%] w-[60%] h-[60%] bg-[#10b981]/10 blur-[120px] rounded-full animate-pulse" />
          <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-blue-500/5 blur-[120px] rounded-full" />
          <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 mix-blend-overlay pointer-events-none" />
        </div>

        {/* Header / Logo */}
        <div className="relative z-10">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-10 h-10 bg-[#10b981] rounded-xl flex items-center justify-center shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-transform group-hover:scale-110 duration-300">
              <Shield className="w-6 h-6 text-black fill-black" />
            </div>
            <span className="text-2xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">
              SBOM.io
            </span>
          </Link>
        </div>

        {/* Middle Section: Testimonial / Quote */}
        <div className="relative z-10 flex-1 flex flex-col justify-center">
          <div className="max-w-lg">
            <div className="mb-6 inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[11px] font-medium tracking-wider uppercase text-[#10b981]">
              <ShieldCheck className="w-3.5 h-3.5" />
              Enterprise Grade Security
            </div>

            {/*
              FIX 2: The root cause of the before/after-reload layout shift.
              The quote block had `min-h-[160px]` which was too short for the
              longest quote (~220px tall), so on first paint the text overflowed
              and pushed the right panel down. On reload the browser had cached
              styles and rendered correctly.

              Solution: Use a FIXED height that comfortably fits the longest
              quote at all reasonable viewport widths, plus `overflow-hidden`
              so it never bleeds. This gives the layout a stable, predictable
              height on both the SSR pass and the client hydration pass.
            */}
            <div className="relative h-[220px] overflow-hidden">
              <div className="absolute -top-10 -left-6 text-[120px] font-serif text-white/5 select-none leading-none">"</div>
              <p
                className="text-[28px] leading-[1.3] font-serif italic text-gray-200 mb-8 relative z-10 transition-opacity duration-700"
                /*
                  FIX 3: Opacity cross-fade is only meaningful after mount;
                  before mount keep opacity:1 so SSR and first client paint match
                  exactly — eliminating the hydration mismatch warning.
                */
                style={{ opacity: mounted ? 1 : 1 }}
              >
                {quotes[quoteIndex].text}
              </p>
            </div>

            <div className="flex items-center gap-4">
              {/*
                FIX 4: Avatar img was rendered server-side with a URL that
                resolves differently per-quote (seed=Sarah vs seed=Marcus …).
                Because quoteIndex is state, React's SSR always emits index=0,
                but if the interval fired before hydration completed the client
                would try to reconcile a different src → hydration mismatch →
                flicker. Suppress hydration warning on the img and add
                suppression on the surrounding block so React skips diffing it.
              */}
              <div
                className="w-12 h-12 rounded-full overflow-hidden border-2 border-white/10 ring-4 ring-black flex-shrink-0"
                suppressHydrationWarning
              >
                <img
                  src={quotes[quoteIndex].avatar}
                  alt={quotes[quoteIndex].author}
                  className="w-full h-full object-cover"
                  suppressHydrationWarning
                />
              </div>
              <div suppressHydrationWarning>
                <p className="font-semibold text-white text-[15px]">{quotes[quoteIndex].author}</p>
                <p className="text-gray-500 text-[13px]">{quotes[quoteIndex].role}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom: Ecosystem logos */}
        <div className="relative z-10 flex items-center gap-6 opacity-30 grayscale">
          <div className="h-5 w-12 relative">
            <img src="https://upload.wikimedia.org/wikipedia/commons/d/db/Npm-logo.svg" alt="npm" className="h-full w-auto object-contain" />
          </div>
          <div className="h-6 w-6 relative">
            <img src="https://upload.wikimedia.org/wikipedia/commons/c/c3/Python-logo-notext.svg" alt="python" className="h-full w-auto object-contain" />
          </div>
          <div className="h-6 w-20 relative">
            <img src="https://upload.wikimedia.org/wikipedia/commons/7/79/Docker_logo.svg" alt="docker" className="h-full w-auto object-contain" />
          </div>
          <div className="h-6 w-6 relative">
            <img src="https://upload.wikimedia.org/wikipedia/commons/c/c2/GitHub_Invertocat_Logo.svg" alt="github" className="h-full w-auto object-contain" />
          </div>
        </div>
      </div>

      {/* --- RIGHT PANEL: AUTH FORM --- */}
      <div className="flex-1 flex-shrink-0 flex flex-col justify-center items-center px-6 md:px-20 relative bg-black">

        {/* Subtle grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:40px_40px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />

        <div className="w-full max-w-[420px] relative z-10">

          {/* Form Header */}
          <div className="text-center mb-10">
            <h1 className="text-[38px] font-serif font-bold tracking-tight text-white mb-3">
              {isSignUp ? "Join the Vanguard" : "Welcome back"}
            </h1>
            <p className="text-gray-500 text-[15px]">
              {isSignUp
                ? "Protect your supply chain with enterprise-grade SBOMs."
                : "Enter your credentials to access your security dashboard."}
            </p>
          </div>

          {/* Social Auth */}
          <div className="grid grid-cols-1 gap-4 mb-8">
            <Button
              variant="outline"
              type="button"
              disabled={loading !== null}
              onClick={signInWithGitHub}
              className="h-13 rounded-2xl border-white/5 bg-[#111111] hover:bg-[#181818] hover:border-white/10 text-white text-[15px] font-medium transition-all duration-300 group shadow-lg"
              suppressHydrationWarning
            >
              {loading === "github" ? (
                <Loader2 className="mr-2 h-5 w-5 animate-spin" />
              ) : (
                <GithubIcon className="mr-3 h-5 w-5 transition-transform group-hover:scale-110" />
              )}
              Continue with GitHub
            </Button>
          </div>

          {/* Divider */}
          <div className="relative my-8">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-white/5"></div>
            </div>
            <div className="relative flex justify-center text-[10px] uppercase tracking-[0.3em] font-bold text-gray-600">
              <span className="bg-black px-4">Secure Channel</span>
            </div>
          </div>

          {/* Main Form */}
          <form onSubmit={handleEmailAuth} className="space-y-6">
            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-[12px] font-bold uppercase tracking-widest text-gray-400 ml-1">
                  Corporate Email
                </label>
                <div className="relative group">
                  <Input
                    type="email"
                    placeholder="name@company.com"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    disabled={loading !== null}
                    className="h-13 rounded-2xl border-white/5 bg-[#0a0a0a] px-5 text-[15px] text-white transition-all duration-300 focus:bg-[#111] focus:ring-1 focus:ring-[#10b981] placeholder:text-gray-700"
                    suppressHydrationWarning
                  />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between ml-1">
                  <label className="text-[12px] font-bold uppercase tracking-widest text-gray-400">
                    Access Code
                  </label>
                  {!isSignUp && (
                    <Link href="#" className="text-[11px] font-bold text-gray-600 hover:text-[#10b981] transition-colors">
                      Recover access?
                    </Link>
                  )}
                </div>
                <div className="relative group">
                  <Input
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••••••"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={loading !== null}
                    className="h-13 rounded-2xl border-white/5 bg-[#0a0a0a] px-5 pr-14 text-[15px] text-white transition-all duration-300 focus:bg-[#111] focus:ring-1 focus:ring-[#10b981] placeholder:text-gray-700"
                    suppressHydrationWarning
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-5 top-1/2 -translate-y-1/2 text-gray-600 hover:text-white transition-colors p-1"
                    suppressHydrationWarning
                  >
                    {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                  </button>
                </div>
              </div>
            </div>

            <Button
              type="submit"
              disabled={loading !== null}
              className="w-full h-14 rounded-2xl bg-[#10b981] text-black text-[16px] font-black tracking-tight hover:bg-[#059669] hover:shadow-[0_0_30px_rgba(16,185,129,0.2)] transition-all duration-300 active:scale-[0.98] flex items-center justify-center gap-2"
              suppressHydrationWarning
            >
              {loading === "email" ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <>
                  {isSignUp ? "Provision Account" : "Access Dashboard"}
                  <ArrowRight className="w-5 h-5" />
                </>
              )}
            </Button>
          </form>

          {/* Bottom Navigation */}
          <div className="mt-10 text-center space-y-6">
            <button
              onClick={() => setIsSignUp(!isSignUp)}
              className="text-sm font-medium text-gray-500 hover:text-white transition-colors group"
              suppressHydrationWarning
            >
              {isSignUp ? "Already have secure access?" : "Need enterprise-wide protection?"}{" "}
              <span className="text-[#10b981] font-bold group-hover:underline">
                {isSignUp ? "Authenticate here" : "Provision your workspace"}
              </span>
            </button>

            <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 text-[11px] font-bold uppercase tracking-[0.1em] text-gray-700">
              <Link href="#" className="hover:text-gray-400 transition-colors">Privacy Shield</Link>
              <Link href="#" className="hover:text-gray-400 transition-colors">Service Level Agreement</Link>
              <Link href="#" className="hover:text-gray-400 transition-colors">Security Audit</Link>
            </div>
          </div>
        </div>

        {/* Global Notifications */}
        {(message || error) && (
          <div className="fixed bottom-8 left-1/2 -translate-x-1/2 lg:left-auto lg:right-12 lg:translate-x-0 z-50 w-full max-w-sm px-6 lg:px-0">
            <div className={`p-5 rounded-2xl border shadow-2xl animate-in slide-in-from-bottom-5 duration-500 ${
              error
                ? "bg-[#2e1e1e] border-red-500/20 text-red-400"
                : "bg-[#0d2818] border-[#10b981]/20 text-[#10b981]"
            }`}>
              <div className="flex items-start gap-4">
                <div className={`mt-0.5 p-1 rounded-full ${error ? "bg-red-500/10" : "bg-[#10b981]/10"}`}>
                  {error ? <Lock className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                </div>
                <div className="flex-1">
                  <p className="text-sm font-semibold mb-1">{error ? "Security Alert" : "System Notification"}</p>
                  <p className="text-xs opacity-80 leading-relaxed">{message || error}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}