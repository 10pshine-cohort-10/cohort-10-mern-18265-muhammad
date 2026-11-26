import { asyncHandler } from "../../utils/asyncHandler.js";
import { registerSchema } from "./auth.validation.js";
import { registerUser as registerUserService } from "./auth.service.js";
import ApiError from "../../errors/ApiError.js";
import { loginSchema } from "./auth.validation.js";
import { loginUser as loginUserService } from "./auth.service.js";
import { refreshSession } from "./auth.service.js";
import { logoutSession } from "./auth.service.js";


export const registerUser = asyncHandler(async (req, res) => {
    const safeInput = registerSchema.safeParse(req.body);

    if (!safeInput.success) {
        throw new ApiError(400, safeInput.error.issues[0].message);
    }

    const user = await registerUserService(safeInput.data);

    res.status(201).json({
        success: true,
        message: "Registration successful.",
        data: user
    });
});


export const login = asyncHandler(async (req, res) => {
    const safeInput = loginSchema.safeParse(req.body);

    if (!safeInput.success) {
        throw new ApiError(400, safeInput.error.issues[0].message);
    }


    const result = await loginUserService(safeInput.data, {
        userAgent: req.get("user-agent"),
        ipAddress: req.ip
    });

    res.cookie("accessToken", result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 15 * 60 * 1000
    });


    res.cookie("refreshToken", result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 30 * 24 * 60 * 60 * 1000
    });


    res.status(200).json({
        success: true,
        message: "Login successful.",
        data: { user: result.user }
    });
});



export const refreshAccessToken = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        throw new ApiError(401, "Refresh token is missing.");
    }

    const result = await refreshSession(refreshToken);

    res.cookie("accessToken", result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 15 * 60 * 1000
    });

    res.cookie("refreshToken", result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 30 * 24 * 60 * 60 * 1000
    });

    res.status(200).json({
        success: true, message: "Tokens refreshed successfully."
    });
});


export const logout = asyncHandler(async (req, res) => {
    await logoutSession(req.sessionId);

    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax"
    };

    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    res.status(200).json({
        success: true,
        message: "Logout successful."
    });
});