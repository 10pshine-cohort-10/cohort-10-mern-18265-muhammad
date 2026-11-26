const errorMiddleware = (error, req, res, next) => {
    let statusCode = error.statusCode || 500;
    let message = error.message || "Internal Server Error";
    let errors = error.errors || [];

    // JWT errors
    if (error.name === "JsonWebTokenError") {
        statusCode = 401;
        message = "Invalid token.";
    }

    if (error.name === "TokenExpiredError") {
        statusCode = 401;
        message = "Token has expired.";
    }

    // MongoDB duplicate key
    if (error.code === 11000) {
        statusCode = 409;

        const field = Object.keys(error.keyPattern || {})[0];

        message = field
            ? `${field.charAt(0).toUpperCase() + field.slice(1)} already exists.`
            : "Resource already exists.";
    }

    // Invalid MongoDB ObjectId
    if (error.name === "CastError") {
        statusCode = 400;
        message = "Invalid resource id.";
    }

    // Mongoose validation errors
    if (error.name === "ValidationError") {
        statusCode = 400;
        message = "Validation failed.";

        errors = Object.values(error.errors).map(
            (item) => item.message
        );
    }

    res.status(statusCode).json({
        success: false,
        message,
        errors: errors.length ? errors : undefined,
        stack: process.env.NODE_ENV === "production"
            ? undefined
            : error.stack
    });
};

export default errorMiddleware;