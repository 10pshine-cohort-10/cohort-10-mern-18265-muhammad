
import { expect } from "chai";
import sinon from "sinon";
import bcrypt from "bcryptjs";

import User from "../../src/models/User.js";
import Session from "../../src/models/Session.js";

import {  registerUser, loginUser, refreshSession } from "../../src/modules/auth/auth.service.js";


describe("Auth Service - registerUser", () => {

    afterEach(() => {  sinon.restore();  });

    it("should register a new user successfully", async () => {
        sinon.stub(User, "findOne").resolves(null);

        const createStub = sinon.stub(User, "create").callsFake(
            async (userData) => ({
                _id: "user123",
                name: userData.name, email: userData.email, password: userData.password
            })
        );

        const result = await registerUser({
            name: "Fazeel",
            email: "fazeel@example.com",
            password: "password123"
        });

        expect(result).to.have.property("id", "user123");
        expect(result).to.have.property("name", "Fazeel");
        expect(result).to.have.property("email", "fazeel@example.com");

        const savedUser = createStub.firstCall.args[0];

        expect(savedUser.password).to.not.equal("password123");

        const isPasswordHashed = await bcrypt.compare(
            "password123",
            savedUser.password
        );

        expect(isPasswordHashed).to.equal(true);
    });


    it("should reject registration if email already exists", async () => {
        sinon.stub(User, "findOne").resolves({
            _id: "existingUser", email: "fazeel@example.com"
        });

        const createStub = sinon.stub(User, "create");

        let caughtError;

        try {
            await registerUser({
                name: "Fazeel", email: "fazeel@example.com",  password: "password123"
            });
        } catch (error) {
            caughtError = error;
        }

        expect(caughtError).to.exist;
        expect(caughtError.statusCode).to.equal(409);
        expect(caughtError.message).to.equal("Email already exists.");

        expect(createStub.called).to.equal(false);
    });

});


describe("Auth Service - loginUser", () => {

    afterEach(() => {
        sinon.restore();
    });


    it("should login successfully and create a session", async () => {
        const user = {
            _id: "user123", name: "Fazeel", email: "fazeel@example.com",
            password: await bcrypt.hash("password123", 12)
        };

        sinon.stub(User, "findOne").returns({
            select: sinon.stub().resolves(user)
        });

        const createStub = sinon.stub(Session, "create").resolves({ _id: "session123" });

        const result = await loginUser(
            {  email: "fazeel@example.com", password: "password123" },
            { userAgent: "Chrome", ipAddress: "127.0.0.1" }
        );


        expect(result.accessToken).to.be.a("string").and.not.empty;
        expect(result.refreshToken).to.be.a("string").and.not.empty;
        expect(result.refreshToken).to.have.length(128);

        expect(result.user).to.deep.equal({
            id: "user123", name: "Fazeel", email: "fazeel@example.com"
        });

        expect(createStub.calledOnce).to.equal(true);

        const sessionData = createStub.firstCall.args[0];

        expect(sessionData.user).to.equal("user123");

        expect(sessionData.refreshTokenHash).to.be.a("string");
        expect(sessionData.expiresAt).to.be.instanceOf(Date);

        expect(sessionData.userAgent).to.equal("Chrome");
        expect(sessionData.ipAddress).to.equal("127.0.0.1");
    });


    it("should reject login if email does not exist", async () => {
        sinon.stub(User, "findOne").returns({
            select: sinon.stub().resolves(null)
        });

        const createStub = sinon.stub(Session, "create");

        let caughtError;

        try {
            await loginUser({ email: "unknown@example.com", password: "password123"
            });

        } catch (error) {
            caughtError = error;
        }

        expect(caughtError).to.exist;
        expect(caughtError.statusCode).to.equal(401);
        expect(caughtError.message).to.equal("Invalid email or password.");

        expect(createStub.called).to.equal(false);
    });


    it("should reject login if password is incorrect", async () => {
        const user = {
            _id: "user123", email: "fazeel@example.com", password: await bcrypt.hash("correct-password", 12)
        };

        sinon.stub(User, "findOne").returns({
            select: sinon.stub().resolves(user)
        });

        const createStub = sinon.stub(Session, "create");

        let caughtError;

        try {
            await loginUser({
                email: "fazeel@example.com",
                password: "wrong-password"
            });
        } catch (error) {
            caughtError = error;
        }

        expect(caughtError).to.exist;
        expect(caughtError.statusCode).to.equal(401);
        expect(caughtError.message).to.equal("Invalid email or password.");

        expect(createStub.called).to.equal(false);
    });

});



describe("Auth Service - refreshSession", () => {

    afterEach(() => {
        sinon.restore();
    });

    it("should rotate refresh token successfully", async () => {
        const session = {
            _id: "session123",  user: "user123"
        };

        sinon.stub(Session, "findOneAndUpdate").resolves(session);

        sinon.stub(User, "findById").resolves({
            _id: "user123",  name: "Fazeel",  email: "fazeel@example.com"
        });

        const result = await refreshSession("old-refresh-token");

        expect(result.accessToken).to.be.a("string").and.not.empty;
        expect(result.refreshToken).to.be.a("string").and.not.empty;
        expect(result.refreshToken).to.have.length(128);

        const updateStub = Session.findOneAndUpdate;

        expect(updateStub.calledOnce).to.equal(true);

        const updateData = updateStub.firstCall.args[1];

        expect(updateData.$set.refreshTokenHash).to.be.a("string");
        expect(updateData.$set.lastUsedAt).to.be.instanceOf(Date);
    });


   it("should reject an invalid or expired refresh token", async () => {
    const updateStub = sinon.stub(Session, "findOneAndUpdate")
        .resolves(null);

    const userLookupStub = sinon.stub(User, "findById");

    let caughtError;

    try {
        await refreshSession("invalid-refresh-token");
    } catch (error) {
        caughtError = error;
    }

    expect(caughtError).to.exist;
    expect(caughtError.statusCode).to.equal(401);

    expect(updateStub.calledOnce).to.equal(true);
    expect(userLookupStub.called).to.equal(false);
});

});
