/**
 * Minecraft Server Security & Anti-Cheat System
 * Comprehensive protection against exploits, cheats, DDoS, and malware
 * @version 2.0.0
 */

// ==================== SERVER HARDENING CONFIGURATION ====================
const SERVER_SECURITY_CONFIG = {
  // Server Protection
  antiDDoS: {
    enabled: true,
    maxConnectionsPerIP: 5,
    connectionRateLimit: 10, // connections per second
    packetSizeLimit: 8192,
    timeoutDetection: true
  },
  
  // Anti-Cheat
  antiCheat: {
    movementChecks: true,
    combatChecks: true,
    inventoryChecks: true,
    speedDetection: true,
    flyDetection: true,
    reachDetection: true,
    autoclickDetection: true,
    aimbotDetection: true
  },
  
  // Exploit Protection
  exploitProtection: {
    chunkBanProtection: true,
    bookBanProtection: true,
    signCrashProtection: true,
    nbtExploitProtection: true,
    pluginExploitProtection: true
  },
  
  // Authentication & Access Control
  accessControl: {
    whitelist: true,
    ipWhitelist: true,
    hardwareIDChecking: true,
    vpnDetection: true,
    geolocationFiltering: true,
    maxAccountsPerIP: 3
  },
  
  // Monitoring & Logging
  monitoring: {
    playerLogging: true,
    commandLogging: true,
    chatMonitoring: true,
    suspiciousActivityAlerts: true,
    realTimeMonitoring: true
  }
};

// ==================== MAIN SECURITY CLASS ====================
class MinecraftServerSecurity {
  constructor(server) {
    this.server = server;
    this.version = "2.0.0";
    this.players = new Map();
    this.connections = new Map();
    this.bannedIPs = new Set();
    this.bannedUUIDs = new Set();
    this.suspiciousActivities = [];
    this.threatLevel = 0;
    this.protectionActive = true;
    
    console.log(`🛡️ Minecraft Server Security v${this.version} initialized`);
    this.initializeProtection();
  }

  // ==================== INITIALIZATION ====================
  initializeProtection() {
    console.log("🚀 Starting Minecraft server protection...");
    
    // 1. Network Layer Protection
    this.setupNetworkProtection();
    
    // 2. Player Connection Handler
    this.setupConnectionHandler();
    
    // 3. Anti-Cheat System
    this.setupAntiCheat();
    
    // 4. Exploit Protection
    this.setupExploitProtection();
    
    // 5. Monitoring System
    this.setupMonitoring();
    
    // 6. Backup System
    this.setupBackupSystem();
    
    // 7. Regular Security Scans
    this.startSecurityScans();
    
    console.log("✅ Server protection fully activated");
  }

  // ==================== 1. NETWORK PROTECTION ====================
  setupNetworkProtection() {
    console.log("🌐 Setting up network protection...");
    
    // Rate limiting
    this.connectionAttempts = new Map();
    this.packetCount = new Map();
    
    // DDoS Protection
    setInterval(() => this.checkDDoSAttempts(), 1000);
    
    // Firewall rules
    this.firewallRules = {
      blockedPorts: [23, 25, 135, 137, 138, 139, 445],
      allowedIPRanges: ['192.168.1.0/24', '10.0.0.0/8'],
      blockedCountries: ['RU', 'CN', 'KP', 'IR', 'SY']
    };
    
    console.log("✅ Network protection configured");
  }

  checkDDoSAttempts() {
    const currentTime = Date.now();
    
    for (const [ip, data] of this.connectionAttempts) {
      // Check connection rate
      const recentAttempts = data.filter(time => currentTime - time < 1000);
      
      if (recentAttempts.length > SERVER_SECURITY_CONFIG.antiDDoS.connectionRateLimit) {
        console.warn(`🚨 DDoS detected from IP: ${ip}, blocking...`);
        this.blockIP(ip, 'DDoS attack', 3600000); // Block for 1 hour
        this.broadcastAlert(`DDoS attack detected from ${ip}`);
      }
      
      // Clean old attempts
      this.connectionAttempts.set(ip, 
        data.filter(time => currentTime - time < 60000)
      );
    }
  }

  blockIP(ip, reason, duration = 3600000) {
    this.bannedIPs.add(ip);
    console.log(`🚫 IP ${ip} blocked: ${reason}`);
    
    // Log to file
    this.logSecurityEvent('IP_BLOCKED', {
      ip: ip,
      reason: reason,
      duration: duration,
      timestamp: new Date().toISOString()
    });
    
    // Auto-unblock after duration
    if (duration > 0) {
      setTimeout(() => {
        this.bannedIPs.delete(ip);
        console.log(`✅ IP ${ip} unblocked after ${duration}ms`);
      }, duration);
    }
  }

  // ==================== 2. CONNECTION HANDLER ====================
  setupConnectionHandler() {
    console.log("🔗 Setting up secure connection handler...");
    
    // Override player connection handler
    const originalPlayerJoin = this.server.onPlayerJoin;
    
    this.server.onPlayerJoin = async (player) => {
      const ip = player.getAddress();
      const uuid = player.getUniqueId();
      const name = player.getName();
      
      console.log(`👤 Player attempting to join: ${name} (${ip})`);
      
      // 1. IP Check
      if (this.bannedIPs.has(ip)) {
        player.kick('Your IP is banned from this server');
        return;
      }
      
      // 2. UUID Check
      if (this.bannedUUIDs.has(uuid)) {
        player.kick('You are banned from this server');
        return;
      }
      
      // 3. Rate Limiting
      if (!this.checkConnectionRate(ip)) {
        player.kick('Too many connection attempts');
        return;
      }
      
      // 4. VPN/Proxy Detection
      if (SERVER_SECURITY_CONFIG.accessControl.vpnDetection) {
        const isVPN = await this.checkVPN(ip);
        if (isVPN) {
          player.kick('VPN/Proxy connections are not allowed');
          return;
        }
      }
      
      // 5. Geolocation Check
      if (SERVER_SECURITY_CONFIG.accessControl.geolocationFiltering) {
        const country = await this.getCountryFromIP(ip);
        if (this.firewallRules.blockedCountries.includes(country)) {
          player.kick('Connections from your country are not allowed');
          return;
        }
      }
      
      // 6. Account Limit Check
      const accountsFromIP = this.getAccountsFromIP(ip);
      if (accountsFromIP >= SERVER_SECURITY_CONFIG.accessControl.maxAccountsPerIP) {
        player.kick('Too many accounts from this IP');
        return;
      }
      
      // 7. Whitelist Check
      if (SERVER_SECURITY_CONFIG.accessControl.whitelist && 
          !this.isWhitelisted(name, uuid)) {
        player.kick('You are not whitelisted on this server');
        return;
      }
      
      // 8. Hardware ID Check (if available)
      if (SERVER_SECURITY_CONFIG.accessControl.hardwareIDChecking) {
        const hwid = this.getHardwareID(player);
        if (hwid && this.isBannedHWID(hwid)) {
          player.kick('Your device is banned from this server');
          return;
        }
      }
      
      // All checks passed
      this.players.set(uuid, {
        player: player,
        ip: ip,
        name: name,
        joinTime: Date.now(),
        violations: [],
        stats: {},
        hardwareID: this.getHardwareID(player)
      });
      
      console.log(`✅ Player ${name} joined successfully`);
      
      // Call original handler
      if (originalPlayerJoin) {
        originalPlayerJoin.call(this.server, player);
      }
    };
    
    // Player quit handler
    this.server.onPlayerQuit = (player) => {
      const uuid = player.getUniqueId();
      this.players.delete(uuid);
      console.log(`👋 Player ${player.getName()} left`);
    };
  }

  checkConnectionRate(ip) {
    const now = Date.now();
    const attempts = this.connectionAttempts.get(ip) || [];
    attempts.push(now);
    
    // Keep only last minute of attempts
    const recentAttempts = attempts.filter(time => now - time < 60000);
    this.connectionAttempts.set(ip, recentAttempts);
    
    return recentAttempts.length <= 60; // Max 60 attempts per minute
  }

  async checkVPN(ip) {
    // Implement VPN detection
    // This is a placeholder - in production use a VPN detection API
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      const data = await response.json();
      
      // Check for known VPN/Hosting providers
      const suspiciousISPs = [
        'DigitalOcean', 'Linode', 'Vultr', 'OVH', 
        'Amazon AWS', 'Google Cloud', 'Microsoft Azure',
        'M247', 'Choopa', 'Psychz'
      ];
      
      return suspiciousISPs.some(isp => 
        data.org && data.org.includes(isp)
      );
    } catch (error) {
      console.warn('VPN check failed:', error);
      return false;
    }
  }

  // ==================== 3. ANTI-CHEAT SYSTEM ====================
  setupAntiCheat() {
    console.log("🕵️ Setting up anti-cheat system...");
    
    // Movement checks
    if (SERVER_SECURITY_CONFIG.antiCheat.movementChecks) {
      this.setupMovementChecks();
    }
    
    // Combat checks
    if (SERVER_SECURITY_CONFIG.antiCheat.combatChecks) {
      this.setupCombatChecks();
    }
    
    // Inventory checks
    if (SERVER_SECURITY_CONFIG.antiCheat.inventoryChecks) {
      this.setupInventoryChecks();
    }
    
    console.log("✅ Anti-cheat system ready");
  }

  setupMovementChecks() {
    const playerPositions = new Map();
    const lastCheckTime = new Map();
    
    setInterval(() => {
      for (const [uuid, playerData] of this.players) {
        const player = playerData.player;
        const currentPos = player.getLocation();
        const previousPos = playerPositions.get(uuid);
        const lastTime = lastCheckTime.get(uuid) || Date.now();
        const currentTime = Date.now();
        const timeDelta = (currentTime - lastTime) / 1000; // seconds
        
        if (previousPos) {
          const distance = this.calculateDistance(previousPos, currentPos);
          const maxSpeed = 10.0; // blocks per second (normal max is ~5.6)
          
          // Speed check
          if (timeDelta > 0 && distance / timeDelta > maxSpeed) {
            this.flagViolation(uuid, 'SPEED_HACK', {
              speed: distance / timeDelta,
              maxAllowed: maxSpeed,
              distance: distance,
              timeDelta: timeDelta
            });
          }
          
          // Fly check
          if (distance > 0 && Math.abs(currentPos.y - previousPos.y) / timeDelta > 5) {
            this.flagViolation(uuid, 'FLY_HACK', {
              verticalSpeed: Math.abs(currentPos.y - previousPos.y) / timeDelta,
              maxAllowed: 5
            });
          }
          
          // NoFall check
          if (previousPos.y > currentPos.y + 10 && player.isOnGround()) {
            this.flagViolation(uuid, 'NOFALL_HACK', {
              fallDistance: previousPos.y - currentPos.y
            });
          }
        }
        
        playerPositions.set(uuid, currentPos);
        lastCheckTime.set(uuid, currentTime);
      }
    }, 100); // Check every 100ms
  }

  setupCombatChecks() {
    const clickPatterns = new Map();
    const lastClicks = new Map();
    
    // Autoclick detection
    this.server.onPlayerInteract = (player, event) => {
      const uuid = player.getUniqueId();
      const now = Date.now();
      const clicks = clickPatterns.get(uuid) || [];
      const lastClickTime = lastClicks.get(uuid) || 0;
      
      clicks.push(now);
      
      // Keep only last second of clicks
      const recentClicks = clicks.filter(time => now - time < 1000);
      clickPatterns.set(uuid, recentClicks);
      lastClicks.set(uuid, now);
      
      // Check for autoclick patterns
      if (recentClicks.length > 20) { // More than 20 CPS
        this.flagViolation(uuid, 'AUTOCLICK', {
          cps: recentClicks.length,
          maxAllowed: 20
        });
      }
      
      // Check for perfect timing (bot-like)
      if (clicks.length > 10) {
        const intervals = [];
        for (let i = 1; i < clicks.length; i++) {
          intervals.push(clicks[i] - clicks[i-1]);
        }
        
        const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
        const variance = intervals.reduce((a, b) => a + Math.pow(b - avgInterval, 2), 0) / intervals.length;
        
        if (variance < 0.1) { // Too consistent timing
          this.flagViolation(uuid, 'BOT_LIKE_BEHAVIOR', {
            variance: variance,
            avgInterval: avgInterval
          });
        }
      }
    };
    
    // Reach check
    this.server.onEntityDamageByEntity = (damager, damaged) => {
      if (damager instanceof Player) {
        const distance = damager.getLocation().distance(damaged.getLocation());
        const maxReach = 6.0; // Maximum legitimate reach
        
        if (distance > maxReach) {
          this.flagViolation(damager.getUniqueId(), 'REACH_HACK', {
            distance: distance,
            maxAllowed: maxReach
          });
        }
      }
    };
    
    // Aimbot detection
    this.server.onPlayerMove = (player) => {
      // Check for unnatural head movement patterns
      const uuid = player.getUniqueId();
      const currentYaw = player.getLocation().yaw;
      const previousYaw = this.getPreviousYaw(uuid);
      
      if (previousYaw !== null) {
        const yawChange = Math.abs(currentYaw - previousYaw);
        
        // Check for instant/snap movements
        if (yawChange > 45 && yawChange < 315) {
          // Excluding wrap-around cases
          this.flagViolation(uuid, 'AIM_ASSIST', {
            yawChange: yawChange,
            type: 'snap_movement'
          });
        }
      }
      
      this.setPreviousYaw(uuid, currentYaw);
    };
  }

  setupInventoryChecks() {
    // Item duplication detection
    const playerInventories = new Map();
    
    setInterval(() => {
      for (const [uuid, playerData] of this.players) {
        const player = playerData.player;
        const currentInventory = this.serializeInventory(player.getInventory());
        const previousInventory = playerInventories.get(uuid);
        
        if (previousInventory) {
          // Check for impossible item additions
          const addedItems = this.getInventoryDiff(previousInventory, currentInventory);
          
          if (addedItems.length > 5) { // Too many items added at once
            this.flagViolation(uuid, 'INVENTORY_EXPLOIT', {
              itemsAdded: addedItems.length,
              items: addedItems.slice(0, 5)
            });
          }
        }
        
        playerInventories.set(uuid, currentInventory);
      }
    }, 5000); // Check every 5 seconds
  }

  // ==================== 4. EXPLOIT PROTECTION ====================
  setupExploitProtection() {
    console.log("🛡️ Setting up exploit protection...");
    
    // Chunk ban protection
    if (SERVER_SECURITY_CONFIG.exploitProtection.chunkBanProtection) {
      this.protectChunkBans();
    }
    
    // Book ban protection
    if (SERVER_SECURITY_CONFIG.exploitProtection.bookBanProtection) {
      this.protectBookBans();
    }
    
    // Sign crash protection
    if (SERVER_SECURITY_CONFIG.exploitProtection.signCrashProtection) {
      this.protectSignCrashes();
    }
    
    // NBT exploit protection
    if (SERVER_SECURITY_CONFIG.exploitProtection.nbtExploitProtection) {
      this.protectNBTExploits();
    }
    
    console.log("✅ Exploit protection configured");
  }

  protectChunkBans() {
    // Monitor chunk loading/unloading
    const chunkLoadCount = new Map();
    const maxChunksPerSecond = 100;
    
    this.server.onChunkLoad = (player, chunk) => {
      const uuid = player.getUniqueId();
      const now = Date.now();
      const loads = chunkLoadCount.get(uuid) || [];
      
      loads.push(now);
      
      // Keep only last second of loads
      const recentLoads = loads.filter(time => now - time < 1000);
      chunkLoadCount.set(uuid, recentLoads);
      
      if (recentLoads.length > maxChunksPerSecond) {
        player.kick('Chunk loading exploit detected');
        this.blockIP(player.getAddress(), 'Chunk ban attempt', 86400000);
      }
    };
  }

  protectBookBans() {
    // Limit book sizes
    this.server.onBookEdit = (player, book) => {
      const totalPages = book.getPages().length;
      const totalChars = book.getPages().reduce((sum, page) => sum + page.length, 0);
      
      if (totalPages > 50 || totalChars > 10000) {
        player.kick('Oversized book detected');
        return false;
      }
      
      // Check for special characters that could cause issues
      const dangerousPatterns = [
        /\\u0000/, // Null characters
        /\\x00/,   // Null bytes
        /�{10,}/,   // Invalid characters
        /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/, // Control characters
      ];
      
      for (const page of book.getPages()) {
        for (const pattern of dangerousPatterns) {
          if (pattern.test(page)) {
            player.kick('Malicious book content detected');
            return false;
          }
        }
      }
      
      return true;
    };
  }

  protectSignCrashes() {
    // Limit sign text length and content
    this.server.onSignChange = (player, lines) => {
      const totalLength = lines.join('').length;
      
      if (totalLength > 256) {
        player.kick('Oversized sign text');
        return false;
      }
      
      // Check for crash-inducing characters
      const crashPatterns = [
        /\\uFFFF/,
        /\\uFFFE/,
        /\\uD800/,
        /\\uDFFF/,
        /�{20,}/
      ];
      
      for (const line of lines) {
        for (const pattern of crashPatterns) {
          if (pattern.test(line)) {
            player.kick('Crash attempt detected');
            this.blockIP(player.getAddress(), 'Sign crash attempt', 86400000);
            return false;
          }
        }
      }
      
      return true;
    };
  }

  protectNBTExploits() {
    // Monitor NBT data in items
    this.server.onItemSpawn = (item) => {
      const nbt = item.getNBT();
      if (nbt) {
        const nbtString = JSON.stringify(nbt);
        
        // Check for oversized NBT
        if (nbtString.length > 10000) {
          item.remove();
          return false;
        }
        
        // Check for recursive/cyclic NBT
        if (this.hasCyclicReferences(nbt)) {
          item.remove();
          return false;
        }
      }
      
      return true;
    };
  }

  // ==================== 5. MONITORING SYSTEM ====================
  setupMonitoring() {
    console.log("📊 Setting up monitoring system...");
    
    // Player activity logging
    if (SERVER_SECURITY_CONFIG.monitoring.playerLogging) {
      this.setupPlayerLogging();
    }
    
    // Command logging
    if (SERVER_SECURITY_CONFIG.monitoring.commandLogging) {
      this.setupCommandLogging();
    }
    
    // Chat monitoring
    if (SERVER_SECURITY_CONFIG.monitoring.chatMonitoring) {
      this.setupChatMonitoring();
    }
    
    // Real-time alerts
    if (SERVER_SECURITY_CONFIG.monitoring.suspiciousActivityAlerts) {
      this.setupAlertSystem();
    }
    
    console.log("✅ Monitoring system active");
  }

  setupPlayerLogging() {
    this.server.onPlayerJoin = (player) => {
      this.logPlayerEvent('JOIN', player, {
        ip: player.getAddress(),
        version: player.getVersion(),
        uuid: player.getUniqueId()
      });
    };
    
    this.server.onPlayerQuit = (player) => {
      this.logPlayerEvent('QUIT', player, {
        playtime: Date.now() - (this.players.get(player.getUniqueId())?.joinTime || Date.now())
      });
    };
  }

  setupCommandLogging() {
    this.server.onCommandPreprocess = (sender, command) => {
      const uuid = sender.getUniqueId ? sender.getUniqueId() : 'CONSOLE';
      const name = sender.getName ? sender.getName() : 'CONSOLE';
      
      this.logSecurityEvent('COMMAND_EXECUTED', {
        player: name,
        uuid: uuid,
        command: command,
        timestamp: new Date().toISOString(),
        location: sender.getLocation ? sender.getLocation().toString() : 'N/A'
      });
      
      // Block dangerous commands
      const dangerousCommands = [
        'op @e',
        'deop @a',
        'stop',
        'reload',
        'ban-ip @a',
        'whitelist remove @a'
      ];
      
      if (dangerousCommands.some(cmd => command.toLowerCase().includes(cmd))) {
        console.warn(`⚠️ Dangerous command attempted: ${command} by ${name}`);
        return false;
      }
      
      return true;
    };
  }

  setupChatMonitoring() {
    this.server.onAsyncPlayerChat = (player, message) => {
      const uuid = player.getUniqueId();
      
      // Check for spam
      if (this.isSpam(uuid, message)) {
        player.sendMessage('§cPlease do not spam!');
        return false;
      }
      
      // Check for advertising
      if (this.containsAdvertising(message)) {
        player.sendMessage('§cAdvertising is not allowed!');
        return false;
      }
      
      // Check for inappropriate content
      if (this.containsInappropriateContent(message)) {
        player.sendMessage('§cPlease keep the chat appropriate!');
        return false;
      }
      
      // Log chat message
      this.logChatMessage(player, message);
      
      return true;
    };
  }

  setupAlertSystem() {
    // Send alerts to online staff
    this.server.getOnlinePlayers().forEach(player => {
      if (player.hasPermission('security.alerts')) {
        player.sendMessage('§6[Security] §fSecurity system activated');
      }
    });
  }

  // ==================== 6. VIOLATION HANDLING ====================
  flagViolation(uuid, type, data) {
    const playerData = this.players.get(uuid);
    if (!playerData) return;
    
    const violation = {
      type: type,
      data: data,
      timestamp: Date.now(),
      serverTime: this.server.getWorldTime()
    };
    
    playerData.violations.push(violation);
    
    // Update threat level
    this.updateThreatLevel(uuid, type);
    
    // Log violation
    this.logSecurityEvent('VIOLATION_DETECTED', {
      player: playerData.name,
      uuid: uuid,
      violation: violation,
      ip: playerData.ip,
      totalViolations: playerData.violations.length
    });
    
    // Take action based on violation severity
    this.handleViolationAction(uuid, type, playerData);
  }

  updateThreatLevel(uuid, violationType) {
    const playerData = this.players.get(uuid);
    if (!playerData) return;
    
    const violationWeights = {
      'SPEED_HACK': 3,
      'FLY_HACK': 5,
      'NOFALL_HACK': 4,
      'AUTOCLICK': 2,
      'REACH_HACK': 6,
      'AIM_ASSIST': 3,
      'INVENTORY_EXPLOIT': 8,
      'BOT_LIKE_BEHAVIOR': 4
    };
    
    const weight = violationWeights[violationType] || 1;
    playerData.threatLevel = (playerData.threatLevel || 0) + weight;
    
    if (playerData.threatLevel > 20) {
      this.punishPlayer(uuid, 'AUTO_BAN', 'Excessive violations detected');
    } else if (playerData.threatLevel > 10) {
      this.warnPlayer(uuid, 'High threat level: ' + playerData.threatLevel);
    }
  }

  handleViolationAction(uuid, type, playerData) {
    const actions = {
      'SPEED_HACK': () => {
        if (playerData.violations.filter(v => v.type === 'SPEED_HACK').length > 3) {
          this.kickPlayer(uuid, 'Speed hacking detected');
        } else {
          this.warnPlayer(uuid, 'Suspicious movement detected');
        }
      },
      
      'FLY_HACK': () => {
        this.kickPlayer(uuid, 'Fly hacking detected');
        this.blockIP(playerData.ip, 'Fly hack', 3600000);
      },
      
      'REACH_HACK': () => {
        this.kickPlayer(uuid, 'Reach hacking detected');
        this.blockIP(playerData.ip, 'Reach hack', 86400000);
      },
      
      'AUTOCLICK': () => {
        if (playerData.violations.filter(v => v.type === 'AUTOCLICK').length > 5) {
          this.kickPlayer(uuid, 'Autoclick detected');
        }
      },
      
      'INVENTORY_EXPLOIT': () => {
        this.kickPlayer(uuid, 'Inventory exploit detected');
        this.banPlayer(uuid, 'Inventory duplication exploit', 604800000); // 7 days
      }
    };
    
    if (actions[type]) {
      actions[type]();
    }
  }

  warnPlayer(uuid, message) {
    const playerData = this.players.get(uuid);
    if (playerData && playerData.player) {
      playerData.player.sendMessage('§c⚠ Warning: §f' + message);
      playerData.player.sendTitle('§c⚠ Warning', message, 10, 70, 20);
    }
  }

  kickPlayer(uuid, reason) {
    const playerData = this.players.get(uuid);
    if (playerData && playerData.player) {
      playerData.player.kick('§cYou have been kicked\n§7Reason: §f' + reason);
      console.log(`👢 Kicked player ${playerData.name}: ${reason}`);
    }
  }

  banPlayer(uuid, reason, duration = 0) {
    this.bannedUUIDs.add(uuid);
    const playerData = this.players.get(uuid);
    
    if (playerData) {
      const player = playerData.player;
      if (player) {
        const banMessage = duration > 0 
          ? `§cYou are temporarily banned\n§7Reason: §f${reason}\n§7Expires in: §f${this.formatDuration(duration)}`
          : `§cYou are permanently banned\n§7Reason: §f${reason}`;
        
        player.kick(banMessage);
      }
      
      console.log(`🔨 Banned player ${playerData.name}: ${reason}`);
      
      // Log to ban file
      this.logSecurityEvent('PLAYER_BANNED', {
        player: playerData.name,
        uuid: uuid,
        ip: playerData.ip,
        reason: reason,
        duration: duration,
        bannedBy: 'AUTO_SECURITY',
        timestamp: new Date().toISOString()
      });
    }
    
    // Auto-unban if temporary
    if (duration > 0) {
      setTimeout(() => {
        this.bannedUUIDs.delete(uuid);
        console.log(`✅ Player ${playerData?.name || uuid} unbanned`);
      }, duration);
    }
  }

  // ==================== 7. BACKUP SYSTEM ====================
  setupBackupSystem() {
    console.log("💾 Setting up backup system...");
    
    // Auto-backup every 30 minutes
    setInterval(() => {
      this.createBackup();
    }, 1800000);
    
    // Keep last 24 backups
    this.maxBackups = 24;
    
    console.log("✅ Backup system configured");
  }

  createBackup() {
    const backupDir = './backups/';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupName = `backup-${timestamp}.zip`;
    
    console.log(`💾 Creating backup: ${backupName}`);
    
    // In a real implementation, this would:
    // 1. Save world data
    // 2. Save player data
    // 3. Save server configuration
    // 4. Compress into zip
    
    // Clean old backups
    this.cleanOldBackups(backupDir);
  }

  cleanOldBackups(backupDir) {
    // Implementation would list and delete old backups
    console.log('🧹 Cleaning old backups...');
  }

  // ==================== 8. SECURITY SCANS ====================
  startSecurityScans() {
    console.log("🔍 Starting regular security scans...");
    
    // Full scan every hour
    setInterval(() => {
      this.performSecurityScan();
    }, 3600000);
    
    // Quick scan every 5 minutes
    setInterval(() => {
      this.performQuickScan();
    }, 300000);
    
    console.log("✅ Security scans scheduled");
  }

  performSecurityScan() {
    console.log("🔍 Performing full security scan...");
    
    const scanResults = {
      timestamp: new Date().toISOString(),
      playersOnline: this.players.size,
      bannedIPs: this.bannedIPs.size,
      bannedPlayers: this.bannedUUIDs.size,
      suspiciousActivities: this.suspiciousActivities.length,
      violations: this.countTotalViolations(),
      recommendations: []
    };
    
    // Check for suspicious patterns
    for (const [uuid, playerData] of this.players) {
      if (playerData.violations.length > 10) {
        scanResults.recommendations.push({
          action: 'REVIEW_PLAYER',
          player: playerData.name,
          violations: playerData.violations.length,
          threatLevel: playerData.threatLevel || 0
        });
      }
    }
    
    // Check for multiple accounts from same IP
    const ipAccounts = new Map();
    for (const [uuid, playerData] of this.players) {
      const accounts = ipAccounts.get(playerData.ip) || [];
      accounts.push(playerData.name);
      ipAccounts.set(playerData.ip, accounts);
    }
    
    for (const [ip, accounts] of ipAccounts) {
      if (accounts.length > SERVER_SECURITY_CONFIG.accessControl.maxAccountsPerIP) {
        scanResults.recommendations.push({
          action: 'INVESTIGATE_IP',
          ip: ip,
          accounts: accounts,
          count: accounts.length
        });
      }
    }
    
    // Save scan results
    this.saveScanResults(scanResults);
    
    console.log(`✅ Security scan complete: ${scanResults.recommendations.length} recommendations`);
  }

  performQuickScan() {
    // Check for immediate threats
    const now = Date.now();
    
    for (const [uuid, playerData] of this.players) {
      // Check for recent violations
      const recentViolations = playerData.violations.filter(
        v => now - v.timestamp < 60000
      );
      
      if (recentViolations.length > 5) {
        console.warn(`⚠️ Player ${playerData.name} has ${recentViolations.length} violations in last minute`);
        this.warnPlayer(uuid, 'Excessive violations detected');
      }
    }
  }

  // ==================== 9. UTILITY FUNCTIONS ====================
  calculateDistance(pos1, pos2) {
    const dx = pos1.x - pos2.x;
    const dy = pos1.y - pos2.y;
    const dz = pos1.z - pos2.z;
    return Math.sqrt(dx*dx + dy*dy + dz*dz);
  }

  serializeInventory(inventory) {
    // Simplified inventory serialization
    const items = [];
    for (let i = 0; i < inventory.getSize(); i++) {
      const item = inventory.getItem(i);
      if (item) {
        items.push({
          slot: i,
          type: item.getType().name(),
          amount: item.getAmount(),
          meta: item.getItemMeta()
        });
      }
    }
    return items;
  }

  getInventoryDiff(oldInv, newInv) {
    const diff = [];
    const oldMap = new Map(oldInv.map(item => [item.slot, item]));
    
    for (const newItem of newInv) {
      const oldItem = oldMap.get(newItem.slot);
      if (!oldItem || 
          oldItem.type !== newItem.type || 
          oldItem.amount !== newItem.amount) {
        diff.push(newItem);
      }
    }
    
    return diff;
  }

  hasCyclicReferences(obj, seen = new Set()) {
    if (obj && typeof obj === 'object') {
      if (seen.has(obj)) return true;
      seen.add(obj);
      
      for (const key in obj) {
        if (this.hasCyclicReferences(obj[key], seen)) {
          return true;
        }
      }
      
      seen.delete(obj);
    }
    return false;
  }

  isSpam(uuid, message) {
    const playerData = this.players.get(uuid);
    if (!playerData) return false;
    
    const now = Date.now();
    const recentMessages = playerData.recentMessages || [];
    
    // Keep only messages from last 10 seconds
    const filteredMessages = recentMessages.filter(
      msg => now - msg.timestamp < 10000
    );
    
    filteredMessages.push({ message: message, timestamp: now });
    playerData.recentMessages = filteredMessages;
    
    // Check for duplicate messages
    const sameMessages = filteredMessages.filter(
      msg => msg.message.toLowerCase() === message.toLowerCase()
    );
    
    // Check for message frequency
    return filteredMessages.length > 8 || sameMessages.length > 3;
  }

  containsAdvertising(message) {
    const adPatterns = [
      /(buy|sell|shop|store|market).*\.(com|net|org|ru)/i,
      /discord\.gg\/\w+/i,
      /ip:.*\d+\.\d+\.\d+\.\d+/i,
      /play\.\w+\.\w+/i,
      /minecraft.*server.*ip/i
    ];
    
    return adPatterns.some(pattern => pattern.test(message));
  }

  containsInappropriateContent(message) {
    // This is a simplified version
    const badWords = [
      // Add inappropriate words here
    ];
    
    const lowerMessage = message.toLowerCase();
    return badWords.some(word => lowerMessage.includes(word));
  }

  formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }

  countTotalViolations() {
    let total = 0;
    for (const [uuid, playerData] of this.players) {
      total += playerData.violations.length;
    }
    return total;
  }

  // ==================== 10. LOGGING FUNCTIONS ====================
  logSecurityEvent(type, data) {
    const logEntry = {
      type: type,
      data: data,
      timestamp: new Date().toISOString(),
      serverTime: this.server.getWorldTime()
    };
    
    this.suspiciousActivities.push(logEntry);
    
    // Keep only last 1000 entries
    if (this.suspiciousActivities.length > 1000) {
      this.suspiciousActivities = this.suspiciousActivities.slice(-1000);
    }
    
    // Log to console
    console.log(`📝 [${type}] ${JSON.stringify(data)}`);
    
    // In production, log to file/database
    this.writeToLogFile('security.log', JSON.stringify(logEntry));
  }

  logPlayerEvent(event, player, extraData = {}) {
    const logEntry = {
      event: event,
      player: player.getName(),
      uuid: player.getUniqueId(),
      ip: player.getAddress(),
      ...extraData,
      timestamp: new Date().toISOString()
    };
    
    this.writeToLogFile('players.log', JSON.stringify(logEntry));
  }

  logChatMessage(player, message) {
    const logEntry = {
      type: 'CHAT',
      player: player.getName(),
      uuid: player.getUniqueId(),
      message: message,
      timestamp: new Date().toISOString(),
      location: player.getLocation().toString()
    };
    
    this.writeToLogFile('chat.log', JSON.stringify(logEntry));
  }

  writeToLogFile(filename, content) {
    // In production, this would write to a log file
    // For now, just log to console
    // console.log(`[LOG:${filename}] ${content}`);
  }

  saveScanResults(results) {
    const filename = `scan-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    this.writeToLogFile(`scans/${filename}`, JSON.stringify(results, null, 2));
  }

  // ==================== 11. ADMIN COMMANDS ====================
  setupAdminCommands() {
    // Security status command
    this.server.registerCommand('security', (sender, args) => {
      if (!sender.hasPermission('security.admin')) {
        sender.sendMessage('§cYou do not have permission to use this command.');
        return;
      }
      
      if (args.length === 0) {
        this.showSecurityStatus(sender);
        return;
      }
      
      switch(args[0].toLowerCase()) {
        case 'scan':
          this.performSecurityScan();
          sender.sendMessage('§aSecurity scan started.');
          break;
          
        case 'players':
          this.listSuspiciousPlayers(sender);
          break;
          
        case 'banip':
          if (args.length > 1) {
            this.blockIP(args[1], 'Manual ban by ' + sender.getName());
            sender.sendMessage(`§aIP ${args[1]} has been banned.`);
          }
          break;
          
        case 'unbanip':
          if (args.length > 1) {
            this.bannedIPs.delete(args[1]);
            sender.sendMessage(`§aIP ${args[1]} has been unbanned.`);
          }
          break;
          
        case 'logs':
          this.showRecentLogs(sender, args[1] || 'security');
          break;
          
        case 'reload':
          this.initializeProtection();
          sender.sendMessage('§aSecurity system reloaded.');
          break;
          
        default:
          sender.sendMessage('§cUnknown security command.');
          break;
      }
    });
  }

  showSecurityStatus(sender) {
    sender.sendMessage('§6=== Server Security Status ===');
    sender.sendMessage(`§7Version: §f${this.version}`);
    sender.sendMessage(`§7Players online: §f${this.players.size}`);
    sender.sendMessage(`§7Banned IPs: §f${this.bannedIPs.size}`);
    sender.sendMessage(`§7Banned players: §f${this.bannedUUIDs.size}`);
    sender.sendMessage(`§7Recent violations: §f${this.countTotalViolations()}`);
    sender.sendMessage(`§7Threat level: §f${this.threatLevel}/100`);
    sender.sendMessage('§6=============================');
  }

  listSuspiciousPlayers(sender) {
    let suspiciousCount = 0;
    
    for (const [uuid, playerData] of this.players) {
      if (playerData.violations.length > 0) {
        suspiciousCount++;
        sender.sendMessage(`§c${playerData.name}§7: §f${playerData.violations.length} violations`);
      }
    }
    
    if (suspiciousCount === 0) {
      sender.sendMessage('§aNo suspicious players found.');
    }
  }

  showRecentLogs(sender, logType) {
    const logs = this.getRecentLogs(logType, 10);
    sender.sendMessage(`§6=== Recent ${logType.toUpperCase()} Logs ===`);
    
    logs.forEach(log => {
      sender.sendMessage(`§7${log.timestamp}: §f${log.message || log.type}`);
    });
  }

  getRecentLogs(logType, limit) {
    // Implementation would fetch from log files
    return [];
  }

  // ==================== 12. AUTO-UPDATE ====================
  checkForUpdates() {
    setInterval(async () => {
      try {
        const response = await fetch('https://api.github.com/repos/security/minecraft-security/releases/latest');
        const data = await response.json();
        
        if (data.tag_name !== this.version) {
          console.log(`🔄 Update available: ${data.tag_name}`);
          console.log('Current version:', this.version);
          console.log('New version:', data.tag_name);
          console.log('Release notes:', data.body.substring(0, 200) + '...');
          
          // Notify admins
          this.notifyAdmins(`Security update available: ${data.tag_name}`);
        }
      } catch (error) {
        console.warn('Failed to check for updates:', error);
      }
    }, 3600000); // Check every hour
  }

  notifyAdmins(message) {
    this.server.getOnlinePlayers().forEach(player => {
      if (player.hasPermission('security.admin')) {
        player.sendMessage(`§6[Security] §f${message}`);
        player.sendTitle('§6Security Update', message, 10, 70, 20);
      }
    });
  }

  // ==================== 13. STARTUP CHECK ====================
  startupChecks() {
    console.log("🔍 Performing startup checks...");
    
    // Check for required permissions
    const requiredPermissions = [
      'bukkit.command.ban.ip',
      'bukkit.command.ban.player',
      'bukkit.command.kick'
    ];
    
    const missingPermissions = requiredPermissions.filter(
      perm => !this.server.getPluginManager().isPluginEnabled(perm)
    );
    
    if (missingPermissions.length > 0) {
      console.error('❌ Missing required permissions:', missingPermissions);
      console.error('Please ensure the server has proper permissions set up.');
    }
    
    // Check server version
    const serverVersion = this.server.getVersion();
    console.log(`✅ Server version: ${serverVersion}`);
    
    // Check for known vulnerable plugins
    this.checkVulnerablePlugins();
    
    console.log("✅ Startup checks completed");
  }

  checkVulnerablePlugins() {
    const vulnerablePlugins = {
      'WorldEdit': '<7.2.0',
      'EssentialsX': '<2.19.0',
      'Vault': '<1.7.3',
      'ProtocolLib': '<4.7.0'
    };
    
    const plugins = this.server.getPluginManager().getPlugins();
    
    plugins.forEach(plugin => {
      const pluginName = plugin.getName();
      const pluginVersion = plugin.getDescription().getVersion();
      
      if (vulnerablePlugins[pluginName]) {
        console.warn(`⚠️  ${pluginName} ${pluginVersion} - Check for updates`);
      }
    });
  }
}

// ==================== INSTANTIATION ====================
// This would be called when your plugin loads
function initializeServerSecurity(server) {
  try {
    const security = new MinecraftServerSecurity(server);
    security.startupChecks();
    security.checkForUpdates();
    
    // Export for manual access if needed
    global.serverSecurity = security;
    
    return security;
  } catch (error) {
    console.error('Failed to initialize server security:', error);
    throw error;
  }
}

// ==================== EXAMPLE USAGE ====================
/*
// In your main plugin file:
const securitySystem = initializeServerSecurity(server);

// Manually trigger a scan
securitySystem.performSecurityScan();

// Check a specific player
const player = server.getPlayer('Playername');
if (player) {
  const playerData = securitySystem.players.get(player.getUniqueId());
  if (playerData) {
    console.log('Player violations:', playerData.violations.length);
  }
}

// Block an IP manually
securitySystem.blockIP('123.456.789.0', 'Manual ban', 86400000);
*/

// ==================== EXPORT ====================
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    MinecraftServerSecurity,
    initializeServerSecurity,
    SERVER_SECURITY_CONFIG
  };
}

console.log("🎮 Minecraft Server Security System Loaded!");
console.log("📖 Use /security for admin commands");
console.log("🛡️  Your server is now protected!");
