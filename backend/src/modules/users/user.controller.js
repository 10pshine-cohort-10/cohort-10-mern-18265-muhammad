import { asyncHandler } from "../../utils/asyncHandler.js";


export const getCurrentUser = asyncHandler(async (req, res) => {
    res.status(200).json({
        success: true,
        message: "User profile fetched successfully.",
        data: {
            user: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                createdAt: req.user.createdAt
            }
        }
    });
});