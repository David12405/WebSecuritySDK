/**
 * Hardcoded deterministic data for api-target.
 * No random IDs, no database, no mutation.
 */

export const USERS = Object.freeze([
  { id: 1, username: "alice", email: "alice@example.com", role: "admin" },
  { id: 2, username: "bob", email: "bob@example.com", role: "analyst" },
  { id: 3, username: "charlie", email: "charlie@example.com", role: "viewer" }
]);

export const PRODUCTS = Object.freeze([
  { id: 1, name: "Web Security Handbook", category: "book", price: 29.99, inStock: true },
  { id: 2, name: "Network Protocol Internals", category: "book", price: 39.50, inStock: true },
  { id: 3, name: "Hardware Security Key", category: "electronics", price: 49.00, inStock: true },
  { id: 4, name: "Managed Router v2", category: "electronics", price: 120.00, inStock: false }
]);
