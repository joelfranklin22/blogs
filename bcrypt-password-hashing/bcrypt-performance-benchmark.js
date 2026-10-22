import bcrypt from "bcrypt";

// Number of users and bcrypt cost factor
const users = 10;
const saltRounds = 10;

const password = "Joel2004@";

// 1. Generate salt and hash password
const salt = bcrypt.genSaltSync(saltRounds);
const passwordHash = await bcrypt.hash(password, salt);

console.log("Generated Hash:", passwordHash);

// 2. Measure hashing time for ONE user
console.time("Single User Hashing");

await bcrypt.hash(password, saltRounds);

console.timeEnd("Single User Hashing");

// 3. Measure hashing time for MULTIPLE users

async function measureHashingTime(userCount, saltRounds) {
  const promises = [];
  console.time(`${userCount} Users - ${saltRounds} Rounds`);

  for (let i = 0; i < userCount; i++) {
    promises.push(bcrypt.hash(password, saltRounds));
  }
  console.timeEnd(`${userCount} Users - ${saltRounds} Rounds`);
}

// Test different configurations

// 1 user and 10 rounds
await measureHashingTime(1, 10);

// 10 users and 10 rounds
await measureHashingTime(10, 10);

//10000 users and 10 rounds
await measureHashingTime(10000, 10);

// 10 user and 20 rounds
await measureHashingTime(10, 20);
