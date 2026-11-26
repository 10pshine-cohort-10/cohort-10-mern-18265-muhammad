import bcrypt from "bcryptjs";
import User from "../../models/User.js";

import Session from "../../models/Session.js";
import ApiError from "../../errors/ApiError.js";
import { generateAccessToken, generateRefreshToken, hashRefreshToken } from "../../utils/generateTokens.js";



export const registerUser = async ({ name, email, password }) => {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
        throw new ApiError(409, "Email already exists.");
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({ name,  email,  password: hashedPassword });

    return { id: user._id, name: user.name, email: user.email };
};


export const loginUser = async ({ email, password }, metadata = {}) => {
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
        throw new ApiError(401, "Invalid email or password.");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        throw new ApiError(401, "Invalid email or password.");
    }

    const refreshToken = generateRefreshToken();

    const expiresAt = new Date( Date.now() + 30 * 24 * 60 * 60 * 1000 );

    const session = await Session.create({
        user: user._id,
        refreshTokenHash: hashRefreshToken(refreshToken),
        expiresAt, userAgent: metadata.userAgent,  ipAddress: metadata.ipAddress
    });

    const accessToken = generateAccessToken(user._id, session._id);

    return {
        accessToken, refreshToken,
        user: {
            id: user._id,  name: user.name,  email: user.email
        }
    };

};



export const refreshSession = async (refreshToken) => {
    const oldTokenHash = hashRefreshToken(refreshToken);

    const newRefreshToken = generateRefreshToken();
    const newTokenHash = hashRefreshToken(newRefreshToken);


    const session = await Session.findOneAndUpdate(
        {
            refreshTokenHash: oldTokenHash, revokedAt: null,
            expiresAt: { $gt: new Date() }
        },
        {
            $set: {
                refreshTokenHash: newTokenHash, lastUsedAt: new Date()
            }
        },
        {
            new: true
        }
    );


    if (!session) {
        throw new ApiError(401, "Invalid or expired refresh token. Please login again.");
    }

    const user = await User.findById(session.user);

    if (!user) {
        throw new ApiError(401, "User no longer exists. Please login again.");
    }

    const accessToken = generateAccessToken(user._id, session._id);

    return { accessToken, refreshToken: newRefreshToken };
};



export const logoutSession = async (sessionId) => {
    await Session.findOneAndUpdate(
        {
            _id: sessionId, revokedAt: null
        },
        {
            $set: {
                revokedAt: new Date(),  revokeReason: "logout"
            }
        }
    );
};