// Gestion sécurisée des tokens JWT côté client
// Ce module fournit des fonctions pour stocker, récupérer et valider les tokens JWT

const JWT_TOKEN_KEY = 'jwt_token';
const JWT_REFRESH_KEY = 'jwt_refresh';
const JWT_EXPIRY_KEY = 'jwt_expiry';

export interface JWTPayload {
    id: number;
    email: string;
    roles: string[];
    exp: number;
    iat: number;
}

export interface AuthResponse {
    token: string;
    user: {
        id: number;
        email: string;
        roles: string[];
    };
}

/**
 * Parse un token JWT et retourne le payload
 * Utilise une méthode sécurisée pour décoder le token
 */
export function parseJwt(token: string): JWTPayload | null {
    try {
        if (!token || typeof token !== 'string') {
            return null;
        }

        // Vérifier que le token a le bon format (3 parties séparées par des points)
        const parts = token.split('.');
        if (parts.length !== 3) {
            return null;
        }

        const base64Url = parts[1];
        
        // Remplacer les caractères spécifiques de base64url par base64 standard
        const base64 = base64Url
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        // Ajouter du padding si nécessaire
        const padding = base64.length % 4;
        const paddedBase64 = padding > 0 ? base64 + '='.repeat(4 - padding) : base64;

        // Décoder le base64
        const jsonPayload = decodeURIComponent(
            atob(paddedBase64)
                .split('')
                .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );

        const payload = JSON.parse(jsonPayload);

        // Valider que le payload contient les champs requis
        if (!payload.exp || !payload.iat || !payload.id) {
            return null;
        }

        return payload as JWTPayload;
    } catch (error) {
        // Logger l'erreur en développement
        if (process.env.NODE_ENV === 'development') {
            console.error('Error parsing JWT:', error);
        }
        return null;
    }
}

/**
 * Stocke le token JWT de manière sécurisée
 * Le token est stocké dans localStorage pour persister entre les sessions
 */
export function setToken(token: string): void {
    if (!token || typeof token !== 'string') {
        throw new Error('Invalid token provided');
    }

    // Parser et valider le token avant de le stocker
    const payload = parseJwt(token);
    if (payload === null) {
        throw new Error('Invalid JWT token format');
    }

    // Vérifier que le token n'est pas expiré
    if (payload.exp * 1000 < Date.now()) {
        throw new Error('Token is already expired');
    }

    // Stocker le token dans localStorage
    try {
        localStorage.setItem(JWT_TOKEN_KEY, token);
        localStorage.setItem(JWT_EXPIRY_KEY, payload.exp.toString());
    } catch (error) {
        // Si localStorage n'est pas disponible (ex: navigation privée)
        console.error('Failed to store token:', error);
        throw new Error('Unable to store authentication token');
    }
}

/**
 * Stocke le refresh token pour le renouvellement automatique
 */
export function setRefreshToken(refreshToken: string): void {
    if (!refreshToken || typeof refreshToken !== 'string') {
        throw new Error('Invalid refresh token provided');
    }

    try {
        localStorage.setItem(JWT_REFRESH_KEY, refreshToken);
    } catch (error) {
        console.error('Failed to store refresh token:', error);
    }
}

/**
 * Récupère le token JWT stocké
 * Retourne null si le token est expiré ou inexistant
 */
export function getToken(): string | null {
    const token = localStorage.getItem(JWT_TOKEN_KEY);
    
    if (token === null) {
        return null;
    }

    // Vérifier si le token est expiré
    const expiry = localStorage.getItem(JWT_EXPIRY_KEY);
    if (expiry) {
        const expiryDate = new Date(parseInt(expiry) * 1000);
        if (expiryDate < new Date()) {
            // Le token est expiré, nettoyer le storage
            removeToken();
            return null;
        }
    }

    return token;
}

/**
 * Récupère le refresh token
 */
export function getRefreshToken(): string | null {
    return localStorage.getItem(JWT_REFRESH_KEY);
}

/**
 * Supprime tous les tokens d'authentification
 * À appeler lors de la déconnexion
 */
export function removeToken(): void {
    localStorage.removeItem(JWT_TOKEN_KEY);
    localStorage.removeItem(JWT_EXPIRY_KEY);
    localStorage.removeItem(JWT_REFRESH_KEY);
}

/**
 * Vérifie si l'utilisateur est actuellement authentifié
 */
export function isAuthenticated(): boolean {
    const token = getToken();
    return token !== null && parseJwt(token) !== null;
}

/**
 * Vérifie si le token expire bientôt (dans les prochaines minutes)
 */
export function isTokenExpiringSoon(thresholdMinutes: number = 5): boolean {
    const token = getToken();
    if (token === null) {
        return false;
    }

    const payload = parseJwt(token);
    if (payload === null) {
        return true;
    }

    const expiryTime = payload.exp * 1000;
    const thresholdTime = Date.now() + thresholdMinutes * 60 * 1000;

    return expiryTime <= thresholdTime;
}

/**
 * Génère les headers d'authentification pour les requêtes API
 */
export function getAuthHeaders(): HeadersInit {
    const token = getToken();
    
    const headers: HeadersInit = {
        'Content-Type': 'application/json',
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    return headers;
}

/**
 * Génère les headers avec le refresh token pour le renouvellement
 */
export function getRefreshAuthHeaders(): HeadersInit {
    const refreshToken = getRefreshToken();
    
    return {
        'Content-Type': 'application/json',
        'X-Refresh-Token': refreshToken || '',
    };
}

/**
 * Calcule le temps restant avant expiration du token en secondes
 */
export function getTokenTimeRemaining(): number {
    const token = getToken();
    if (token === null) {
        return 0;
    }

    const payload = parseJwt(token);
    if (payload === null) {
        return 0;
    }

    const expiryTime = payload.exp * 1000;
    const remaining = expiryTime - Date.now();

    return Math.max(0, Math.floor(remaining / 1000));
}

/**
 * Vérifie si le token est valide (format et expiration)
 */
export function isTokenValid(token: string): boolean {
    const payload = parseJwt(token);
    return payload !== null && payload.exp * 1000 > Date.now();
}

/**
 * Decode seulement (sans vérification d'expiration)
 * Utile pour l'affichage de données non critiques
 */
export function decodeTokenUnsafe(token: string): Record<string, unknown> | null {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return null;
        }

        const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(
            atob(base64)
                .split('')
                .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );

        return JSON.parse(jsonPayload);
    } catch {
        return null;
    }
}
