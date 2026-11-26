import crypto from "node:crypto";
import jwt from "jsonwebtoken";

export const generateAccessToken = (userId, sessionId) => {
    return jwt.sign(
        {
            sub: userId.toString(),
            sid: sessionId.toString()
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m"
        }
    );
};

export const generateRefreshToken = () => {
    return crypto.randomBytes(64).toString("hex");
};

export const hashRefreshToken = (token) => {
    return crypto.createHash("sha256").update(token).digest("hex");
};