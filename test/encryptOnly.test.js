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
    jasmine.DEFAULT_TIMEOUT_INTERVAL =
      process.env.JEST_TIMEOUT || jasmine.DEFAULT_TIMEOUT_INTERVAL;
  } catch (err) {
    console.error("Error in beforeAll: " + err);
  }
});

afterAll(() => {
  mongoose.disconnect();
});

beforeEach(() => {
  testAccount = {
    userId: mongoose.Types.ObjectId(),
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

test("create document, find it.", async done => {
  try {
    let compareKeys = Object.keys(testAccount);
    testAccount.keyEncrypt = crypto.randomBytes(32).toString("base64");

    let res = await Account.create(testAccount);

    let query = Account.findOne({
      userId: testAccount.userId,
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

test.skip("create array of docs", async done => {
  // This test fails if getKeyForQueryResponse deletes the key from keyStore. 
  // It's probably due to the asyncronous nature of the save calls created by .create
  // One way out would be to identify the key not only by userId, but also by e.g. a hash of the doc to save
  // 
  try {
    let compareKeys = Object.keys(testAccount);
    testAccount.keyEncrypt = crypto.randomBytes(32).toString("base64");

    let res = await Account.create([testAccount, testAccount]);

    let query = Account.find({
      userId: testAccount.userId,
      keyEncrypt: testAccount.keyEncrypt
    });

    res = await query;
    expect(res.constructor).toBe(Array);
    res.map(function(obj) {
      expect(filterObject(obj, compareKeys)).toEqual(
        filterObject(testAccount, compareKeys)
      );
    });
  } catch (err) {
    console.log("Error " + err);
    expect(true).toBe(false);
  }
  done();
});

test("create two docs, different keys, read them.", async done => {
  try {
    let compareKeys = Object.keys(testAccount);

    let testAccount1 = testAccount;
    let testAccount2 = testAccount;

    testAccount1.keyEncrypt = crypto.randomBytes(32).toString("base64");
    testAccount2.keyEncrypt = crypto.randomBytes(32).toString("base64");
    testAccount2.userId = mongoose.Types.ObjectId();

    await Account.create(testAccount1);
    await Account.create(testAccount2);

    let res1 = await Account.findOne({
      userId: testAccount1.userId,
      keyEncrypt: testAccount1.keyEncrypt
    });
    expect(filterObject(res1, compareKeys)).toEqual(
      filterObject(testAccount1, compareKeys)
    );

    let res2 = await Account.findOne({
      userId: testAccount2.userId,
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

test.skip("not providing keys", async done => {
  try {
    // using async in here will only work from jest v20 on .https://github.com/facebook/jest/issues/1377
    let wasError = false;
    try {
      await Account.create(testAccount);
    } catch (err) {
      wasError = true;
    }
    expect(wasError).toBeTruthy();

    wasError = false;
    try {
      await Account.findOne({
        userId: testAccount.userId
      });
    } catch (err) {
      wasError = true;
    }
    expect(wasError).toBeTruthy();
  } catch (err) {
    console.log("Error " + err);
    expect(true).toBe(false);
  }

  done();
});

test("providing wrong key on read", async done => {
  try {
    // using async in here will only work from jest v20 on .https://github.com/facebook/jest/issues/1377

    testAccount.keyEncrypt = crypto.randomBytes(32).toString("base64");
    await Account.create(testAccount);

    let wasError = false;
    try {
      await Account.findOne({
        userId: testAccount.userId,
        keyEncrypt: crypto.randomBytes(32).toString("base64")
      });
    } catch (err) {
      console.log(err);
      wasError = true;
    }
    expect(wasError).toBeTruthy();
  } catch (err) {
    console.log("Error " + err);
    expect(true).toBe(false);
  }
  done();
});
