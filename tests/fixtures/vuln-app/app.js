// Deliberately vulnerable fixture for sec-scan tests. Do not use in production.
function handler(userInput) {
  return eval(userInput); // insecure: arbitrary code execution
}
module.exports = { handler };
