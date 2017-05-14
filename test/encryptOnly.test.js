//require("../index");

var mongoose = require("mongoose");
var Mockgoose = require("mockgoose").Mockgoose;
var mockgoose = new Mockgoose(mongoose);
var crypto = require("crypto");
mongoose.set("debug", true);

var config = {
  db: process.env.MONGODB_URI || "mongodb://localhost/tpfdb"
};

require("./account.model");
var Account = mongoose.model("Account");

var testAccount;

//var moment = require("moment");

beforeAll(async () => {
  try {
    mongoose.disconnect();
    await mockgoose.prepareStorage();
    await mongoose.connect(config.db);
    jasmine.DEFAULT_TIMEOUT_INTERVAL = process.env.JEST_TIMEOUT ||
      jasmine.DEFAULT_TIMEOUT_INTERVAL;
  } catch (err) {
    console.error("Error in beforeAll: " + err);
  }
});

afterAll(() => {
  mongoose.disconnect();
});

beforeEach(() => {
  testAccount = {
    userID: mongoose.Types.ObjectId(),
    bankID: mongoose.Types.ObjectId(),
    blz: 21812712,
    name: "Konto"
  };
  //  await mockgoose.helper.reset();
});

/* Helper functions*/

filterObject = (obj, keysSelect) => {
  let newObj = {};
  keysSelect.map(function(key) {
    newObj[key] = obj[key];
  });
  return newObj;
};

test("create document", async done => {
  try {
    let compareKeys = Object.keys(testAccount);
    testAccount.keyEncrypt = crypto.randomBytes(32).toString("base64");

    let res = await Account.create(testAccount);

    let query = Account.findOne({
      userID: testAccount.userID,
      keyEncrypt: testAccount.keyEncrypt
    });

    res = await query;
    expect(filterObject(res, compareKeys)).toEqual(
      filterObject(testAccount, compareKeys)
    );
  } catch (err) {
    console.log("Error " + err);
    expect(true).toBe(false);
  }
  done();
});

test("create two docs, different keys", async done => {
  try {
    let compareKeys = Object.keys(testAccount);

    let testAccount1 = testAccount;
    let testAccount2 = testAccount;

    testAccount1.keyEncrypt = crypto.randomBytes(32).toString("base64");
    testAccount2.keyEncrypt = crypto.randomBytes(32).toString("base64");
    testAccount2.userID = mongoose.Types.ObjectId();

    await Account.create(testAccount1);
    await Account.create(testAccount2);

    let res1 = await Account.findOne({
      userID: testAccount1.userID,
      keyEncrypt: testAccount1.keyEncrypt
    });
    expect(filterObject(res1, compareKeys)).toEqual(
      filterObject(testAccount1, compareKeys)
    );

    let res2 = await Account.findOne({
      userID: testAccount2.userID,
      keyEncrypt: testAccount2.keyEncrypt
    });

    expect(filterObject(res2, compareKeys)).toEqual(
      filterObject(testAccount2, compareKeys)
    );
  } catch (err) {
    console.log("Error " + err);
    expect(true).toBe(false);
  }
  done();
});

test("not providing keys", async done => {
  // using async in here will only work from jest v20 on .https://github.com/facebook/jest/issues/1377
  try {
    expect(await Account.create(testAccount)).toThrow();
  } catch (err) {
  }

  try {
    expect(
      await Account.findOne({
        userID: testAccount.userID
      })
    ).toThrow();
  } catch (err) {
  }

  done();
});

test("providing wrong key on read", async done => {
  // using async in here will only work from jest v20 on .https://github.com/facebook/jest/issues/1377

  testAccount.keyEncrypt = crypto.randomBytes(32).toString("base64");
  await Account.create(testAccount);

  try {
    expect(
      await Account.findOne({
        userID: testAccount.userID,
        keyEncrypt: crypto.randomBytes(32).toString("base64")
      })
    ).toThrow();
  } catch (err) {
  }

  done();
});
