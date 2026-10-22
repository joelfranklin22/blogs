import bcrypt from "bcrypt";

const password = "Joel2004@";
const saltRounds = 10;

// 1. Simulate registration
const storedHash = await bcrypt.hash(password, saltRounds);

console.log("Password hashed successfully");

// 2. Verify correct password and measure time
const enteredPassword = "Joel2004@";

console.time("Password Verification");

const isMatch = await bcrypt.compare(enteredPassword, storedHash);

console.timeEnd("Password Verification");

// 3. Display result
if (isMatch) {
  console.log("Password verified successfully!");
} else {
  console.log("Invalid password!");
}
