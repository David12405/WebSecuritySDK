/**
 * Accurate OpenAPI 3.0.3 document for api-target.
 * Strictly matches implemented endpoints, parameters, request bodies, and responses.
 */

export const OPENAPI_SPEC = Object.freeze({
  openapi: "3.0.3",
  info: {
    title: "Recon Test Target — REST API",
    version: "1.0.0",
    description: "Deterministic REST API designed for API discovery and OpenAPI 3.x parser validation in Module 1."
  },
  servers: [
    {
      url: "/",
      description: "Default server (relative)"
    }
  ],
  paths: {
    "/api/users": {
      get: {
        operationId: "getUsers",
        summary: "Retrieve user list with optional id filter",
        parameters: [
          {
            name: "id",
            in: "query",
            required: false,
            description: "Filter by user ID",
            schema: {
              type: "integer"
            }
          }
        ],
        responses: {
          "200": {
            description: "User list retrieved successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    users: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          id: { type: "integer" },
                          username: { type: "string" },
                          email: { type: "string" },
                          role: { type: "string" }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            description: "Invalid user id supplied"
          }
        }
      }
    },
    "/api/users/{id}": {
      get: {
        operationId: "getUserById",
        summary: "Retrieve single user by ID",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            description: "User ID",
            schema: {
              type: "integer"
            }
          }
        ],
        responses: {
          "200": {
            description: "User details",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    user: {
                      type: "object",
                      properties: {
                        id: { type: "integer" },
                        username: { type: "string" },
                        email: { type: "string" },
                        role: { type: "string" }
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            description: "Invalid user ID"
          },
          "404": {
            description: "User not found"
          }
        }
      }
    },
    "/api/search": {
      post: {
        operationId: "searchProducts",
        summary: "Search products with keyword and nested filter object",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["keyword"],
                properties: {
                  keyword: {
                    type: "string",
                    description: "Search keyword"
                  },
                  filters: {
                    type: "object",
                    description: "Filter criteria",
                    properties: {
                      category: {
                        type: "string",
                        description: "Product category"
                      },
                      minPrice: {
                        type: "number",
                        description: "Minimum product price"
                      }
                    }
                  }
                }
              }
            }
          }
        },
        responses: {
          "200": {
            description: "Search results returned",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    keyword: { type: "string" },
                    results: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          id: { type: "integer" },
                          name: { type: "string" },
                          category: { type: "string" },
                          price: { type: "number" },
                          inStock: { type: "boolean" }
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            description: "Missing keyword or invalid JSON payload"
          },
          "415": {
            description: "Unsupported media type"
          }
        }
      }
    },
    "/api/orders": {
      post: {
        operationId: "createOrder",
        summary: "Submit order with nested shipping destination",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["productId", "quantity", "shipping"],
                properties: {
                  productId: {
                    type: "integer",
                    description: "Product ID"
                  },
                  quantity: {
                    type: "integer",
                    minimum: 1,
                    description: "Order quantity"
                  },
                  shipping: {
                    type: "object",
                    required: ["city", "country"],
                    description: "Shipping destination",
                    properties: {
                      city: {
                        type: "string",
                        description: "Destination city"
                      },
                      country: {
                        type: "string",
                        description: "Destination country code"
                      }
                    }
                  }
                }
              }
            }
          }
        },
        responses: {
          "201": {
            description: "Order created successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    orderId: { type: "string" },
                    status: { type: "string" },
                    productId: { type: "integer" },
                    quantity: { type: "integer" },
                    shipping: {
                      type: "object",
                      properties: {
                        city: { type: "string" },
                        country: { type: "string" }
                      }
                    }
                  }
                }
              }
            }
          },
          "400": {
            description: "Validation error"
          },
          "404": {
            description: "Product not found"
          },
          "415": {
            description: "Unsupported media type"
          }
        }
      }
    },
    "/api/client-info": {
      get: {
        operationId: "getClientInfo",
        summary: "Retrieve client info requiring custom test header",
        parameters: [
          {
            name: "X-Test-Client",
            in: "header",
            required: true,
            description: "Required client identification header",
            schema: {
              type: "string",
              example: "web-security-agent"
            }
          }
        ],
        responses: {
          "200": {
            description: "Client verified successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    client: { type: "string" },
                    status: { type: "string" }
                  }
                }
              }
            }
          },
          "400": {
            description: "Missing or invalid X-Test-Client header"
          }
        }
      }
    }
  }
});
