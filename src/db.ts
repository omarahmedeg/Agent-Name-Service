// src/db.ts

import sqlite3 from "sqlite3";
import fs from "fs";
import path from "path";
import crypto from "crypto";

/**
 * Configuration options for the agent registry
 */
export interface RegistryOptions {
  /**
   * Whether to use persistent storage instead of in-memory database
   */
  persistentStorage?: boolean;

  /**
   * Path to the database file for persistent storage
   */
  dbPath?: string;

  /**
   * Whether to encrypt sensitive data
   */
  encryptData?: boolean;

  /**
   * Secret key for encryption (should be provided via environment variable)
   */
  encryptionKey?: string;

  /**
   * Maximum number of query results to return
   */
  maxQueryResults?: number;
}

/**
 * Default registry options
 */
const DEFAULT_OPTIONS: RegistryOptions = {
  persistentStorage: false,
  dbPath: "./data/agent-registry.db",
  encryptData: false,
  maxQueryResults: 100,
};

/**
 * Agent registry for storing and retrieving agent data
 */
export class AgentRegistry {
  private db!: sqlite3.Database;
  private options: RegistryOptions;
  private initialized: boolean = false;
  private encryptionKey: Buffer | null = null;

  /**
   * Creates a new instance of the agent registry
   * @param options Configuration options
   */
  constructor(options: RegistryOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    // Call synchronous initialization to ensure the database is ready
    this.initializeDatabaseSync();
  }

  /**
   * Initializes the database connection and schema synchronously
   * This ensures the database is ready when the constructor completes
   */
  private initializeDatabaseSync() {
    try {
      // Determine database path
      if (this.options.persistentStorage && this.options.dbPath) {
        // Ensure directory exists
        const dbDir = path.dirname(this.options.dbPath);
        if (!fs.existsSync(dbDir)) {
          fs.mkdirSync(dbDir, { recursive: true });
        }

        // Open or create database file
        this.db = new sqlite3.Database(this.options.dbPath);
        console.log(`Using persistent storage at: ${this.options.dbPath}`);
      } else {
        // Use in-memory database
        this.db = new sqlite3.Database(":memory:");
        console.log("Using in-memory database");
      }

      // Initialize encryption if enabled
      if (this.options.encryptData) {
        // Get encryption key from options or environment variable
        const keyString =
          this.options.encryptionKey || process.env.ANS_ENCRYPTION_KEY;

        if (!keyString) {
          console.warn(
            "Encryption enabled but no key provided. Falling back to unencrypted storage."
          );
          this.options.encryptData = false;
        } else {
          // Create a fixed-length key using a hash of the provided key
          this.encryptionKey = crypto
            .createHash("sha256")
            .update(keyString)
            .digest();
          console.log("Data encryption enabled");
        }
      }

      // Create tables with synchronous execution
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS agents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          card TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Create an index on the name column for faster lookups
      this.db.exec(
        "CREATE INDEX IF NOT EXISTS idx_agents_name ON agents (name)"
      );

      // Add a table for security events
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS security_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          details TEXT,
          agent_name TEXT,
          ip_address TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      this.initialized = true;
    } catch (error) {
      console.error("Failed to initialize database:", error);
      throw new Error(
        `Database initialization failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  /**
   * Saves an agent to the registry
   * @param name The unique name of the agent
   * @param card The agent card data
   * @returns A promise that resolves when the operation is complete
   */
  public async saveAgent(name: string, card: string): Promise<void> {
    this.validateInitialized();

    try {
      // Sanitize inputs to prevent SQL injection
      if (!this.validateAgentName(name)) {
        throw new Error("Invalid agent name");
      }

      // Encrypt the card data if encryption is enabled
      const encryptedCard =
        this.options.encryptData && this.encryptionKey
          ? this.encryptData(card)
          : card;

      // Use parameterized query to prevent SQL injection
      const sql = `
        INSERT OR REPLACE INTO agents (name, card, updated_at) 
        VALUES (?, ?, CURRENT_TIMESTAMP)
      `;

      await this.executeQuery(sql, [name, encryptedCard]);
    } catch (error) {
      console.error("Failed to save agent:", error);
      throw new Error(
        `Failed to save agent: ${this.sanitizeErrorMessage(error)}`
      );
    }
  }

  /**
   * Gets an agent card from the registry
   * @param name The unique name of the agent
   * @returns The agent card, or null if not found
   */
  public async getAgentCard(name: string): Promise<string | null> {
    this.validateInitialized();

    try {
      // Sanitize inputs to prevent SQL injection
      if (!this.validateAgentName(name)) {
        throw new Error("Invalid agent name");
      }

      // Use parameterized query to prevent SQL injection
      const sql = "SELECT card FROM agents WHERE name = ?";

      return new Promise<string | null>((resolve, reject) => {
        this.db.get(sql, [name], (err: Error, row: { card: string }) => {
          if (err) {
            reject(new Error(`Database query failed: ${err.message}`));
            return;
          }

          if (!row) {
            resolve(null);
            return;
          }

          try {
            // Decrypt the card data if encryption is enabled
            const decryptedCard =
              this.options.encryptData && this.encryptionKey
                ? this.decryptData(row.card)
                : row.card;

            resolve(decryptedCard);
          } catch (decryptError) {
            reject(
              new Error(
                `Failed to decrypt agent card: ${this.sanitizeErrorMessage(
                  decryptError
                )}`
              )
            );
          }
        });
      });
    } catch (error) {
      console.error("Failed to get agent card:", error);
      throw new Error(
        `Failed to get agent card: ${this.sanitizeErrorMessage(error)}`
      );
    }
  }

  /**
   * Logs a security event to the database
   * @param eventType Type of security event
   * @param severity Severity of the event
   * @param details Details about the event
   * @param agentName Associated agent name (optional)
   * @param ipAddress Associated IP address (optional)
   */
  public async logSecurityEvent(
    eventType: string,
    severity: string,
    details: string,
    agentName?: string,
    ipAddress?: string
  ): Promise<void> {
    this.validateInitialized();

    try {
      // Use parameterized query to prevent SQL injection
      const sql = `
        INSERT INTO security_events (event_type, severity, details, agent_name, ip_address)
        VALUES (?, ?, ?, ?, ?)
      `;

      await this.executeQuery(sql, [
        eventType,
        severity,
        details,
        agentName,
        ipAddress,
      ]);
    } catch (error) {
      console.error("Failed to log security event:", error);
      // Don't throw here to prevent disrupting the main application flow
    }
  }

  /**
   * Gets security events from the database
   * @param options Query options
   * @returns Array of security events
   */
  public async getSecurityEvents(
    options: {
      eventType?: string;
      severity?: string;
      agentName?: string;
      ipAddress?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<any[]> {
    this.validateInitialized();

    try {
      // Build the query with conditions
      let sql = "SELECT * FROM security_events WHERE 1=1";
      const params: any[] = [];

      if (options.eventType) {
        sql += " AND event_type = ?";
        params.push(options.eventType);
      }

      if (options.severity) {
        sql += " AND severity = ?";
        params.push(options.severity);
      }

      if (options.agentName) {
        sql += " AND agent_name = ?";
        params.push(options.agentName);
      }

      if (options.ipAddress) {
        sql += " AND ip_address = ?";
        params.push(options.ipAddress);
      }

      // Add ordering and limit
      sql += " ORDER BY timestamp DESC";
      sql += " LIMIT ?";

      // Default limit to max results or 100
      const limit = options.limit || this.options.maxQueryResults || 100;
      params.push(limit);

      if (options.offset) {
        sql += " OFFSET ?";
        params.push(options.offset);
      }

      return new Promise<any[]>((resolve, reject) => {
        this.db.all(sql, params, (err: Error, rows: any[]) => {
          if (err) {
            reject(new Error(`Database query failed: ${err.message}`));
            return;
          }

          resolve(rows || []);
        });
      });
    } catch (error) {
      console.error("Failed to get security events:", error);
      throw new Error(
        `Failed to get security events: ${this.sanitizeErrorMessage(error)}`
      );
    }
  }

  /**
   * Gets agents by capabilities from the registry
   * @param capabilities Array of capabilities to search for
   * @param matchAll Whether to match all capabilities (AND) or any capability (OR)
   * @returns Array of agent objects with name and card
   */
  public async getAgentsByCapabilities(
    capabilities: string[],
    matchAll: boolean = false
  ): Promise<Array<{ name: string; card: string }> | null> {
    this.validateInitialized();

    try {
      if (
        !capabilities ||
        !Array.isArray(capabilities) ||
        capabilities.length === 0
      ) {
        throw new Error("Invalid capabilities array");
      }

      // Sanitize capability inputs
      const sanitizedCapabilities = capabilities.filter(
        (cap) => cap && typeof cap === "string" && cap.trim().length > 0
      );

      if (sanitizedCapabilities.length === 0) {
        throw new Error("No valid capabilities provided");
      }

      const sql = "SELECT name, card FROM agents ORDER BY name";

      return new Promise<Array<{ name: string; card: string }> | null>(
        (resolve, reject) => {
          this.db.all(
            sql,
            [],
            (err: Error, rows: Array<{ name: string; card: string }>) => {
              if (err) {
                reject(new Error(`Database query failed: ${err.message}`));
                return;
              }

              if (!rows || rows.length === 0) {
                resolve([]);
                return;
              }

              try {
                const matchingAgents: Array<{ name: string; card: string }> =
                  [];

                for (const row of rows) {
                  try {
                    // Decrypt the card data if encryption is enabled
                    let decryptedCard: string;

                    if (this.options.encryptData && this.encryptionKey) {
                      try {
                        decryptedCard = this.decryptData(row.card);
                      } catch (decryptError) {
                        console.warn(
                          `Failed to decrypt card for ${row.name}:`,
                          decryptError instanceof Error
                            ? decryptError.message
                            : String(decryptError)
                        );
                        continue; // Skip this agent
                      }
                    } else {
                      decryptedCard = row.card;
                    }

                    // Validate that we have a non-empty string
                    if (!decryptedCard || typeof decryptedCard !== "string") {
                      console.warn(
                        `Invalid card data for ${row.name}: empty or not a string`
                      );
                      continue;
                    }

                    // Try to parse the JSON
                    let agentData: any;
                    try {
                      // Check if the card has the "Agent Card for" prefix and extract JSON
                      let jsonString = decryptedCard;

                      // Look for the JSON part after the prefix
                      const jsonStartIndex = decryptedCard.indexOf("{");
                      if (jsonStartIndex > 0) {
                        // Extract everything from the first '{' onwards
                        jsonString = decryptedCard.substring(jsonStartIndex);
                      }

                      agentData = JSON.parse(jsonString);
                    } catch (parseError) {
                      console.warn(
                        `Failed to parse agent card for ${row.name}:`,
                        parseError instanceof Error
                          ? parseError.message
                          : String(parseError)
                      );
                      console.warn(
                        `Card data preview:`,
                        decryptedCard.substring(0, 100) +
                          (decryptedCard.length > 100 ? "..." : "")
                      );
                      continue; // Skip this agent
                    }

                    // Extract capabilities safely
                    let agentCapabilities: string[] = [];

                    // Try multiple paths where capabilities might be stored
                    if (agentData.capabilities) {
                      agentCapabilities = Array.isArray(agentData.capabilities)
                        ? agentData.capabilities
                        : [];
                    } else if (
                      agentData.metadata &&
                      agentData.metadata.capabilities
                    ) {
                      agentCapabilities = Array.isArray(
                        agentData.metadata.capabilities
                      )
                        ? agentData.metadata.capabilities
                        : [];
                    }

                    // Check if agent has the required capabilities
                    const hasCapabilities = matchAll
                      ? sanitizedCapabilities.every((cap) =>
                          agentCapabilities.some((agentCap: string) =>
                            agentCap.toLowerCase().includes(cap.toLowerCase())
                          )
                        )
                      : sanitizedCapabilities.some((cap) =>
                          agentCapabilities.some((agentCap: string) =>
                            agentCap.toLowerCase().includes(cap.toLowerCase())
                          )
                        );

                    if (hasCapabilities) {
                      matchingAgents.push({
                        name: row.name,
                        card: decryptedCard,
                      });
                    }
                  } catch (rowError) {
                    console.warn(
                      `Error processing agent ${row.name}:`,
                      rowError instanceof Error
                        ? rowError.message
                        : String(rowError)
                    );
                    continue; // Skip this agent and continue with others
                  }
                }

                console.log(
                  `Found ${matchingAgents.length} matching agents out of ${rows.length} total`
                );
                resolve(matchingAgents);
              } catch (error) {
                console.error("Error in getAgentsByCapabilities:", error);
                reject(error);
              }
            }
          );
        }
      );
    } catch (error) {
      console.error("Failed to get agents by capabilities:", error);
      throw new Error(
        `Failed to get agents by capabilities: ${this.sanitizeErrorMessage(
          error
        )}`
      );
    }
  }

  /**
   * Closes the database connection
   */
  public async close(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (!this.db) {
        resolve();
        return;
      }

      this.db.close((err) => {
        if (err) {
          reject(new Error(`Failed to close database: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Executes a SQL query on the database
   * @param sql The SQL query to execute
   * @param params Parameters for the query
   * @returns A promise that resolves when the query is complete
   */
  private executeQuery(sql: string, params: any[] = []): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.db.run(sql, params, function (err: Error) {
        if (err) {
          reject(new Error(`SQL execution failed: ${err.message}`));
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Validates that the database is initialized
   * @throws Error if the database is not initialized
   */
  private validateInitialized(): void {
    if (!this.initialized || !this.db) {
      throw new Error("Database not initialized");
    }
  }

  /**
   * Validates an agent name to prevent SQL injection
   * @param name The agent name to validate
   * @returns Whether the name is valid
   */
  private validateAgentName(name: string): boolean {
    if (!name || typeof name !== "string") {
      return false;
    }

    // Allow only alphanumeric characters, dots, hyphens, and underscores
    return /^[a-zA-Z0-9._-]+$/.test(name);
  }

  /**
   * Encrypts data using AES-GCM
   * @param data The data to encrypt
   * @returns The encrypted data as a hex string
   */
  private encryptData(data: string): string {
    if (!this.encryptionKey) {
      throw new Error("Encryption key not set");
    }

    try {
      // Generate a random initialization vector
      const iv = crypto.randomBytes(16);

      // Create a cipher
      const cipher = crypto.createCipheriv(
        "aes-256-gcm",
        this.encryptionKey,
        iv
      );

      // Encrypt the data
      let encrypted = cipher.update(data, "utf8", "hex");
      encrypted += cipher.final("hex");

      // Get the authentication tag
      const authTag = cipher.getAuthTag();

      // Combine IV, encrypted data, and auth tag for storage
      return (
        iv.toString("hex") + ":" + encrypted + ":" + authTag.toString("hex")
      );
    } catch (error) {
      console.error("Encryption failed:", error);
      throw new Error("Failed to encrypt data");
    }
  }

  /**
   * Decrypts data using AES-GCM
   * @param encryptedData The encrypted data as a hex string
   * @returns The decrypted data
   */
  private decryptData(encryptedData: string): string {
    if (!this.encryptionKey) {
      throw new Error("Encryption key not set");
    }

    try {
      // Split the stored data into IV, encrypted data, and auth tag
      const parts = encryptedData.split(":");
      if (parts.length !== 3) {
        throw new Error("Invalid encrypted data format");
      }

      const iv = Buffer.from(parts[0], "hex");
      const encrypted = parts[1];
      const authTag = Buffer.from(parts[2], "hex");

      // Create a decipher
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        this.encryptionKey,
        iv
      );
      decipher.setAuthTag(authTag);

      // Decrypt the data
      let decrypted = decipher.update(encrypted, "hex", "utf8");
      decrypted += decipher.final("utf8");

      return decrypted;
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Failed to decrypt data");
    }
  }

  /**
   * Sanitizes error messages to prevent information leakage
   * @param error The error to sanitize
   * @returns A sanitized error message
   */
  private sanitizeErrorMessage(error: any): string {
    try {
      // Convert to string if not already
      const message = error?.message || String(error);

      // Remove any potentially sensitive information
      return message
        .replace(/(?:\/[\w.-]+)+/g, "[PATH]")
        .replace(/at\s+[\w\s./<>]+\s+\(.*\)/g, "[STACK_TRACE]")
        .replace(
          /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi,
          "[EMAIL]"
        )
        .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[IP_ADDRESS]")
        .replace(/key|secret|password|token|credential|auth/gi, "[SENSITIVE]");
    } catch (e) {
      return "Unknown error";
    }
  }
}
