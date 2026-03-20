import passport from "passport";
import { Strategy as GoogleOAuth2Strategy } from "passport-google-oauth20";
import { getDb } from "./db.js";
import { randomUUID } from "crypto";

export function setupGoogleStrategy() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.warn("[Auth] GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set — Google SSO disabled");
    return;
  }

  passport.use(
    new GoogleOAuth2Strategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID ?? "",
        clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
        callbackURL: `${process.env.BASE_URL ?? "http://localhost:3000"}/auth/google/callback`,
        scope: ["openid", "email", "profile"],
        authorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenURL: "https://oauth2.googleapis.com/token",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      },
      async (_accessToken, _refreshToken, profile, done) => {
        const db = getDb();
        const now = Math.floor(Date.now() / 1000);
        const googleId = profile.id;
        const email = (profile.emails?.[0]?.value) ?? "";
        const name = profile.displayName ?? "";
        const picture = profile.photos?.[0]?.value ?? null;

        const existing = db.exec("SELECT id FROM users WHERE google_id = ?", [googleId]);
        if (existing.length && existing[0].values.length) {
          const userId = existing[0].values[0][0] as string;
          return done(null, { id: userId, email, name, picture });
        }

        const userId = randomUUID();
        db.run(
          "INSERT INTO users (id, google_id, email, name, picture, created_at) VALUES (?,?,?,?,?,?)",
          [userId, googleId, email, name, picture, now]
        );

        return done(null, { id: userId, email, name, picture });
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((user: Express.User, done) => {
    done(null, user);
  });
}

export { passport };
