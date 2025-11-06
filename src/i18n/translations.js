/**
 * Internationalization (i18n) System
 * Supports multiple languages for global reach
 */

export const translations = {
  en: {
    // Extension metadata
    extensionName: 'Anti-Phishing Guardian',
    extensionDescription: 'Detect and block phishing links in Gmail and Outlook',
    
    // Popup UI
    dashboard: 'Dashboard',
    lists: 'Lists',
    settings: 'Settings',
    
    // Dashboard
    protectionOverview: 'Protection Overview',
    linksScanned: 'Links Scanned',
    threatsBlocked: 'Threats Blocked',
    protectionRate: 'Protection Rate',
    
    // Threat Database
    threatDatabase: 'Threat Database',
    knownThreats: 'Known Threats',
    lastUpdated: 'Last Updated',
    status: 'Status',
    updateDatabase: 'Update Database',
    upToDate: 'Up to date',
    updateAvailable: 'Update available',
    notDownloaded: 'Not downloaded',
    
    // Quick Actions
    quickActions: 'Quick Actions',
    exportData: 'Export Data',
    clearCache: 'Clear Cache',
    viewReports: 'View Reports',
    systemCheck: 'System Check',
    
    // Lists Management
    whitelist: 'Whitelist (Trusted Sites)',
    blacklist: 'Blacklist (Blocked Sites)',
    addDomain: 'Add',
    enterDomain: 'Enter domain (e.g., example.com)',
    noDomains: 'No domains added',
    
    // Settings
    notificationSettings: 'Notification Settings',
    notifyDangerous: 'Notify on dangerous threats',
    notifySuspicious: 'Notify on suspicious links',
    notifyUpdates: 'Notify on database updates',
    
    protectionLevel: 'Protection Level',
    strict: 'Strict (Aggressive spam detection)',
    balanced: 'Balanced (Recommended)',
    permissive: 'Permissive (Allow more)',
    
    dataManagement: 'Data Management',
    exportSettings: 'Export Settings',
    importSettings: 'Import Settings',
    backupCloud: 'Backup to Cloud',
    restoreCloud: 'Restore from Cloud',
    factoryReset: 'Factory Reset',
    
    about: 'About',
    version: 'Version',
    builtWith: 'Built with ❤️ for your security',
    
    // Notifications
    threatBlocked: 'Threat Blocked!',
    suspiciousLink: 'Suspicious Link Detected',
    phishingAttempt: 'Phishing Attempt',
    linkBlocked: 'Link has been blocked for your safety',
    
    // Toast messages
    settingsSaved: 'Settings saved',
    dataExported: 'Data exported',
    cacheCleared: 'Cache cleared',
    databaseUpdated: 'Database updated successfully',
    domainAdded: 'Added to',
    domainRemoved: 'Removed from',
    invalidDomain: 'Invalid domain format',
    enterValidDomain: 'Please enter a domain',
    
    // Threat levels
    safe: 'Safe',
    suspicious: 'Suspicious',
    dangerous: 'Dangerous',
    unknown: 'Unknown',
    
    // Confirmations
    confirmClearCache: 'Clear all cached threat analysis?',
    confirmFactoryReset: 'Factory reset will delete ALL data. Continue?',
    confirmAbsolutely: 'Are you absolutely sure? This cannot be undone!',
    
    // System health
    systemHealthCheck: 'System Health Check',
    database: 'Database',
    ok: 'OK',
    missing: 'Missing',
    domains: 'domains',
    extensionRunning: 'Extension: Running',
    
    // ML/AI
    mlDetected: 'ML detected',
    highRiskPatterns: 'high-risk patterns',
    confidence: 'confidence'
  },
  
  es: {
    // Spanish translations
    extensionName: 'Guardián Anti-Phishing',
    extensionDescription: 'Detectar y bloquear enlaces de phishing en Gmail y Outlook',
    
    dashboard: 'Panel',
    lists: 'Listas',
    settings: 'Configuración',
    
    protectionOverview: 'Resumen de Protección',
    linksScanned: 'Enlaces Escaneados',
    threatsBlocked: 'Amenazas Bloqueadas',
    protectionRate: 'Tasa de Protección',
    
    threatDatabase: 'Base de Datos de Amenazas',
    knownThreats: 'Amenazas Conocidas',
    lastUpdated: 'Última Actualización',
    status: 'Estado',
    updateDatabase: 'Actualizar Base de Datos',
    upToDate: 'Actualizado',
    updateAvailable: 'Actualización disponible',
    notDownloaded: 'No descargado',
    
    quickActions: 'Acciones Rápidas',
    exportData: 'Exportar Datos',
    clearCache: 'Limpiar Caché',
    viewReports: 'Ver Informes',
    systemCheck: 'Verificación del Sistema',
    
    whitelist: 'Lista Blanca (Sitios Confiables)',
    blacklist: 'Lista Negra (Sitios Bloqueados)',
    addDomain: 'Agregar',
    enterDomain: 'Ingrese dominio (ej: ejemplo.com)',
    noDomains: 'No hay dominios agregados',
    
    notificationSettings: 'Configuración de Notificaciones',
    notifyDangerous: 'Notificar en amenazas peligrosas',
    notifySuspicious: 'Notificar en enlaces sospechosos',
    notifyUpdates: 'Notificar actualizaciones de base de datos',
    
    protectionLevel: 'Nivel de Protección',
    strict: 'Estricto (Detección agresiva de spam)',
    balanced: 'Equilibrado (Recomendado)',
    permissive: 'Permisivo (Permitir más)',
    
    dataManagement: 'Gestión de Datos',
    exportSettings: 'Exportar Configuración',
    importSettings: 'Importar Configuración',
    backupCloud: 'Respaldo en la Nube',
    restoreCloud: 'Restaurar desde la Nube',
    factoryReset: 'Restablecer de Fábrica',
    
    about: 'Acerca de',
    version: 'Versión',
    builtWith: 'Hecho con ❤️ para tu seguridad',
    
    threatBlocked: '¡Amenaza Bloqueada!',
    suspiciousLink: 'Enlace Sospechoso Detectado',
    phishingAttempt: 'Intento de Phishing',
    linkBlocked: 'El enlace ha sido bloqueado por tu seguridad',
    
    settingsSaved: 'Configuración guardada',
    dataExported: 'Datos exportados',
    cacheCleared: 'Caché limpiado',
    databaseUpdated: 'Base de datos actualizada exitosamente',
    domainAdded: 'Agregado a',
    domainRemoved: 'Eliminado de',
    invalidDomain: 'Formato de dominio inválido',
    enterValidDomain: 'Por favor ingrese un dominio',
    
    safe: 'Seguro',
    suspicious: 'Sospechoso',
    dangerous: 'Peligroso',
    unknown: 'Desconocido',
    
    confirmClearCache: '¿Limpiar todo el análisis de amenazas en caché?',
    confirmFactoryReset: 'El restablecimiento eliminará TODOS los datos. ¿Continuar?',
    confirmAbsolutely: '¿Estás absolutamente seguro? ¡Esto no se puede deshacer!',
    
    systemHealthCheck: 'Verificación de Salud del Sistema',
    database: 'Base de Datos',
    ok: 'OK',
    missing: 'Faltante',
    domains: 'dominios',
    extensionRunning: 'Extensión: Ejecutándose',
    
    mlDetected: 'ML detectó',
    highRiskPatterns: 'patrones de alto riesgo',
    confidence: 'confianza'
  },
  
  fr: {
    // French translations
    extensionName: 'Gardien Anti-Hameçonnage',
    extensionDescription: 'Détecter et bloquer les liens de phishing dans Gmail et Outlook',
    
    dashboard: 'Tableau de bord',
    lists: 'Listes',
    settings: 'Paramètres',
    
    protectionOverview: 'Aperçu de la Protection',
    linksScanned: 'Liens Analysés',
    threatsBlocked: 'Menaces Bloquées',
    protectionRate: 'Taux de Protection',
    
    threatDatabase: 'Base de Données des Menaces',
    knownThreats: 'Menaces Connues',
    lastUpdated: 'Dernière Mise à Jour',
    status: 'Statut',
    updateDatabase: 'Mettre à Jour la Base',
    upToDate: 'À jour',
    updateAvailable: 'Mise à jour disponible',
    notDownloaded: 'Non téléchargé',
    
    quickActions: 'Actions Rapides',
    exportData: 'Exporter les Données',
    clearCache: 'Vider le Cache',
    viewReports: 'Voir les Rapports',
    systemCheck: 'Vérification Système',
    
    whitelist: 'Liste Blanche (Sites de Confiance)',
    blacklist: 'Liste Noire (Sites Bloqués)',
    addDomain: 'Ajouter',
    enterDomain: 'Entrer le domaine (ex: exemple.com)',
    noDomains: 'Aucun domaine ajouté',
    
    notificationSettings: 'Paramètres de Notification',
    notifyDangerous: 'Notifier les menaces dangereuses',
    notifySuspicious: 'Notifier les liens suspects',
    notifyUpdates: 'Notifier les mises à jour',
    
    protectionLevel: 'Niveau de Protection',
    strict: 'Strict (Détection agressive des spams)',
    balanced: 'Équilibré (Recommandé)',
    permissive: 'Permissif (Autoriser plus)',
    
    dataManagement: 'Gestion des Données',
    exportSettings: 'Exporter les Paramètres',
    importSettings: 'Importer les Paramètres',
    backupCloud: 'Sauvegarde Cloud',
    restoreCloud: 'Restaurer du Cloud',
    factoryReset: 'Réinitialisation d\'Usine',
    
    about: 'À propos',
    version: 'Version',
    builtWith: 'Fait avec ❤️ pour votre sécurité',
    
    threatBlocked: 'Menace Bloquée!',
    suspiciousLink: 'Lien Suspect Détecté',
    phishingAttempt: 'Tentative de Hameçonnage',
    linkBlocked: 'Le lien a été bloqué pour votre sécurité',
    
    settingsSaved: 'Paramètres sauvegardés',
    dataExported: 'Données exportées',
    cacheCleared: 'Cache vidé',
    databaseUpdated: 'Base de données mise à jour avec succès',
    domainAdded: 'Ajouté à',
    domainRemoved: 'Supprimé de',
    invalidDomain: 'Format de domaine invalide',
    enterValidDomain: 'Veuillez entrer un domaine',
    
    safe: 'Sûr',
    suspicious: 'Suspect',
    dangerous: 'Dangereux',
    unknown: 'Inconnu',
    
    confirmClearCache: 'Effacer toutes les analyses de menaces en cache?',
    confirmFactoryReset: 'La réinitialisation supprimera TOUTES les données. Continuer?',
    confirmAbsolutely: 'Êtes-vous absolument sûr? Cela ne peut pas être annulé!',
    
    systemHealthCheck: 'Vérification de la Santé du Système',
    database: 'Base de Données',
    ok: 'OK',
    missing: 'Manquant',
    domains: 'domaines',
    extensionRunning: 'Extension: En cours d\'exécution',
    
    mlDetected: 'ML a détecté',
    highRiskPatterns: 'schémas à haut risque',
    confidence: 'confiance'
  },
  
  de: {
    // German translations
    extensionName: 'Anti-Phishing-Wächter',
    extensionDescription: 'Phishing-Links in Gmail und Outlook erkennen und blockieren',
    
    dashboard: 'Dashboard',
    lists: 'Listen',
    settings: 'Einstellungen',
    
    protectionOverview: 'Schutzübersicht',
    linksScanned: 'Links Gescannt',
    threatsBlocked: 'Bedrohungen Blockiert',
    protectionRate: 'Schutzrate',
    
    threatDatabase: 'Bedrohungsdatenbank',
    knownThreats: 'Bekannte Bedrohungen',
    lastUpdated: 'Zuletzt Aktualisiert',
    status: 'Status',
    updateDatabase: 'Datenbank Aktualisieren',
    upToDate: 'Aktuell',
    updateAvailable: 'Update verfügbar',
    notDownloaded: 'Nicht heruntergeladen',
    
    quickActions: 'Schnellaktionen',
    exportData: 'Daten Exportieren',
    clearCache: 'Cache Leeren',
    viewReports: 'Berichte Anzeigen',
    systemCheck: 'Systemprüfung',
    
    whitelist: 'Whitelist (Vertrauenswürdige Seiten)',
    blacklist: 'Blacklist (Blockierte Seiten)',
    addDomain: 'Hinzufügen',
    enterDomain: 'Domain eingeben (z.B. beispiel.de)',
    noDomains: 'Keine Domains hinzugefügt',
    
    notificationSettings: 'Benachrichtigungseinstellungen',
    notifyDangerous: 'Bei gefährlichen Bedrohungen benachrichtigen',
    notifySuspicious: 'Bei verdächtigen Links benachrichtigen',
    notifyUpdates: 'Bei Datenbank-Updates benachrichtigen',
    
    protectionLevel: 'Schutzstufe',
    strict: 'Streng (Aggressive Spam-Erkennung)',
    balanced: 'Ausgewogen (Empfohlen)',
    permissive: 'Tolerant (Mehr Zulassen)',
    
    dataManagement: 'Datenverwaltung',
    exportSettings: 'Einstellungen Exportieren',
    importSettings: 'Einstellungen Importieren',
    backupCloud: 'Cloud-Backup',
    restoreCloud: 'Aus Cloud Wiederherstellen',
    factoryReset: 'Werkseinstellungen',
    
    about: 'Über',
    version: 'Version',
    builtWith: 'Mit ❤️ für Ihre Sicherheit erstellt',
    
    threatBlocked: 'Bedrohung Blockiert!',
    suspiciousLink: 'Verdächtiger Link Erkannt',
    phishingAttempt: 'Phishing-Versuch',
    linkBlocked: 'Link wurde zu Ihrer Sicherheit blockiert',
    
    settingsSaved: 'Ein stellungen gespeichert',
    dataExported: 'Daten exportiert',
    cacheCleared: 'Cache geleert',
    databaseUpdated: 'Datenbank erfolgreich aktualisiert',
    domainAdded: 'Hinzugefügt zu',
    domainRemoved: 'Entfernt von',
    invalidDomain: 'Ungültiges Domain-Format',
    enterValidDomain: 'Bitte geben Sie eine Domain ein',
    
    safe: 'Sicher',
    suspicious: 'Verdächtig',
    dangerous: 'Gefährlich',
    unknown: 'Unbekannt',
    
    confirmClearCache: 'Alle zwischengespeicherten Bedrohungsanalysen löschen?',
    confirmFactoryReset: 'Zurücksetzen löscht ALLE Daten. Fortfahren?',
    confirmAbsolutely: 'Sind Sie absolut sicher? Dies kann nicht rückgängig gemacht werden!',
    
    systemHealthCheck: 'Systemgesundheitsprüfung',
    database: 'Datenbank',
    ok: 'OK',
    missing: 'Fehlend',
    domains: 'Domains',
    extensionRunning: 'Erweiterung: Läuft',
    
    mlDetected: 'ML erkannt',
    highRiskPatterns: 'Hochrisiko-Muster',
    confidence: 'Vertrauen'
  },
  
  zh: {
    // Chinese (Simplified) translations
    extensionName: '反网络钓鱼卫士',
    extensionDescription: '检测并阻止 Gmail 和 Outlook 中的钓鱼链接',
    
    dashboard: '仪表板',
    lists: '列表',
    settings: '设置',
    
    protectionOverview: '保护概览',
    linksScanned: '已扫描链接',
    threatsBlocked: '已阻止威胁',
    protectionRate: '保护率',
    
    threatDatabase: '威胁数据库',
    knownThreats: '已知威胁',
    lastUpdated: '最后更新',
    status: '状态',
    updateDatabase: '更新数据库',
    upToDate: '最新',
    updateAvailable: '有可用更新',
    notDownloaded: '未下载',
    
    quickActions: '快速操作',
    exportData: '导出数据',
    clearCache: '清除缓存',
    viewReports: '查看报告',
    systemCheck: '系统检查',
    
    whitelist: '白名单（信任的网站）',
    blacklist: '黑名单（已阻止的网站）',
    addDomain: '添加',
    enterDomain: '输入域名（例如：example.com）',
    noDomains: '未添加域名',
    
    notificationSettings: '通知设置',
    notifyDangerous: '危险威胁通知',
    notifySuspicious: '可疑链接通知',
    notifyUpdates: '数据库更新通知',
    
    protectionLevel: '保护级别',
    strict: '严格（主动垃圾邮件检测）',
    balanced: '平衡（推荐）',
    permissive: '宽松（允许更多）',
    
    dataManagement: '数据管理',
    exportSettings: '导出设置',
    importSettings: '导入设置',
    backupCloud: '备份到云',
    restoreCloud: '从云恢复',
    factoryReset: '恢复出厂设置',
    
    about: '关于',
    version: '版本',
    builtWith: '用 ❤️ 为您的安全而构建',
    
    threatBlocked: '威胁已阻止！',
    suspiciousLink: '检测到可疑链接',
    phishingAttempt: '网络钓鱼尝试',
    linkBlocked: '为了您的安全，链接已被阻止',
    
    settingsSaved: '设置已保存',
    dataExported: '数据已导出',
    cacheCleared: '缓存已清除',
    databaseUpdated: '数据库更新成功',
    domainAdded: '已添加到',
    domainRemoved: '已从中删除',
    invalidDomain: '域名格式无效',
    enterValidDomain: '请输入域名',
    
    safe: '安全',
    suspicious: '可疑',
    dangerous: '危险',
    unknown: '未知',
    
    confirmClearCache: '清除所有缓存的威胁分析？',
    confirmFactoryReset: '恢复出厂设置将删除所有数据。继续？',
    confirmAbsolutely: '您确定吗？此操作无法撤消！',
    
    systemHealthCheck: '系统健康检查',
    database: '数据库',
    ok: '正常',
    missing: '缺失',
    domains: '域名',
    extensionRunning: '扩展：运行中',
    
    mlDetected: 'ML 检测到',
    highRiskPatterns: '高风险模式',
    confidence: '置信度'
  }
};

// Default language
export const defaultLanguage = 'en';

// Get browser language
export function getBrowserLanguage() {
  const lang = navigator.language || navigator.userLanguage;
  const shortLang = lang.split('-')[0];
  return translations[shortLang] ? shortLang : defaultLanguage;
}

// i18n function
export function t(key, lang = null) {
  const currentLang = lang || getBrowserLanguage();
  return translations[currentLang]?.[key] || translations[defaultLanguage][key] || key;
}
