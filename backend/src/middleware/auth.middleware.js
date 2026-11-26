import jwt from "jsonwebtoken";
import User from "../models/User.js";
import Session from "../models/Session.js";
import ApiError from "../errors/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";

export const protect = asyncHandler(async (req, res, next) => {
    const accessToken = req.cookies.accessToken;

    if (!accessToken) {
        throw new ApiError(401, "Not authorized.");
    }

    let decoded;

    try {
        decoded = jwt.verify(
            accessToken,
            process.env.ACCESS_TOKEN_SECRET
        );
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            throw new ApiError(401, "Access token has expired.");
        }

        if (error.name === "JsonWebTokenError") {
            throw new ApiError(401, "Invalid access token.");
        }

        throw new ApiError(401, "Could not verify access token.");
    }

    const session = await Session.findOne({
        _id: decoded.sid,
        user: decoded.sub,
        revokedAt: null,
        expiresAt: { $gt: new Date() }
    });

    if (!session) {
        throw new ApiError(401, "Session expired or revoked. Please login again.");
    }

    const user = await User.findById(decoded.sub);

    if (!user) {
        throw new ApiError(401, "User no longer exists. Please login again.");
    }

    req.user = user;
    req.sessionId = session._id;

    next();
});