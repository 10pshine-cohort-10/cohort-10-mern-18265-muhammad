
import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        refreshTokenHash: {
            type: String,
            required: true,
            select: false
        },

        expiresAt: {
            type: Date,
            required: true
        },

        revokedAt: {
            type: Date,
            default: null
        },

        revokeReason: {
            type: String,
            enum: ["logout", "reuse_detected", "admin"],
            default: null
        },

        lastUsedAt: {
            type: Date,
            default: Date.now
        },

        userAgent: {
            type: String,
            maxlength: 500
        },

        ipAddress: {
            type: String,
            maxlength: 45
        }
    },
    {
        timestamps: true
    }
);

// Automatically delete expired sessions
sessionSchema.index(
    { expiresAt: 1 },
    { expireAfterSeconds: 0 }
);

// Efficiently find a user's sessions
sessionSchema.index({ user: 1, revokedAt: 1 });

sessionSchema.index(
    { refreshTokenHash: 1 },
    { unique: true }
);

const Session = mongoose.model("Session", sessionSchema);

export default Session;
