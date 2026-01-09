import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode, useRef } from 'react';
import {
    getToken,
    setToken,
    removeToken,
    getAuthHeaders,
    isAuthenticated as checkIsAuthenticated,
    parseJwt,
    isTokenExpiringSoon,
    JWTPayload,
    setRefreshToken,
    getRefreshToken,
    getTokenTimeRemaining,
    AuthResponse,
} from '../../jwt';

// Configuration du hook d'authentification
interface AuthConfig {
    autoRefresh?: boolean;
    refreshThresholdMinutes?: number;
    onSessionExpired?: () => void;
}

interface AuthContextType {
    // État d'authentification
    isAuthenticated: boolean;
    isLoading: boolean;
    
    // Données utilisateur
    user: JWTPayload | null;
    userEmail: string | null;
    userRoles: string[];
    
    // Données du token
    token: string | null;
    tokenExpiry: number | null;
    timeRemaining: number;
    
    // Actions
    login: (email: string, password: string) => Promise<boolean>;
    logout: () => void;
    refreshAuth: () => Promise<boolean>;
    
    // Erreurs
    error: AuthError | null;
    clearError: () => void;
    
    // Accès aux données utilisateur
    hasRole: (role: string) => boolean;
    isTokenExpiringSoon: boolean;
}

// Type pour les erreurs d'authentification
interface AuthError {
    code: string;
    message: string;
    details?: unknown;
}

// Constantes pour les codes d'erreur
const ERROR_CODES = {
    NETWORK_ERROR: 'NETWORK_ERROR',
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    ACCOUNT_DISABLED: 'ACCOUNT_DISABLED',
    TOKEN_EXPIRED: 'TOKEN_EXPIRED',
    VALIDATION_ERROR: 'VALIDATION_ERROR',
    UNKNOWN_ERROR: 'UNKNOWN_ERROR',
} as const;

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Provider d'authentification
interface AuthProviderProps {
    children: ReactNode;
    config?: AuthConfig;
}

export function AuthProvider({ children, config }: AuthProviderProps): JSX.Element {
    const {
        autoRefresh = true,
        refreshThresholdMinutes = 5,
        onSessionExpired,
    } = config || {};

    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [token, setTokenState] = useState<string | null>(null);
    const [user, setUser] = useState<JWTPayload | null>(null);
    const [error, setError] = useState<AuthError | null>(null);
    const [isTokenExpiringSoon, setIsTokenExpiringSoonState] = useState(false);
    const [timeRemaining, setTimeRemaining] = useState(0);

    // Ref pour éviter les re-renders en double
    const initializationRef = useRef(false);

    // Initialisation au chargement
    useEffect(() => {
        // Éviter l'initialisation multiple
        if (initializationRef.current) {
            return;
        }
        initializationRef.current = true;

        const storedToken = getToken();
        if (storedToken) {
            const payload = parseJwt(storedToken);
            if (payload && payload.exp * 1000 > Date.now()) {
                setTokenState(storedToken);
                setUser(payload);
                setIsAuthenticated(true);
                setIsTokenExpiringSoonState(isTokenExpiringSoon(refreshThresholdMinutes));
                updateTimeRemaining(payload.exp);
            } else {
                // Token expiré, nettoyer
                removeToken();
            }
        }
        setIsLoading(false);

        // Cleanup function
        return () => {
            initializationRef.current = false;
        };
    }, [refreshThresholdMinutes]);

    // Timer pour mettre à jour le temps restant
    useEffect(() => {
        if (!isAuthenticated) {
            return;
        }

        const interval = setInterval(() => {
            const remaining = getTokenTimeRemaining();
            setTimeRemaining(remaining);
            
            const expiringSoon = remaining > 0 && remaining <= refreshThresholdMinutes * 60;
            setIsTokenExpiringSoonState(expiringSoon);

            if (expiringSoon && autoRefresh) {
                // Déclencher le refresh automatiquement
                refreshAuth().catch(() => {
                    // Si le refresh échoue, déconnecter l'utilisateur
                    if (onSessionExpired) {
                        onSessionExpired();
                    }
                    logout();
                });
            }
        }, 1000);

        return () => clearInterval(interval);
    }, [isAuthenticated, autoRefresh, refreshThresholdMinutes, onSessionExpired]);

    // Met à jour le temps restant basé sur l'expiration du token
    const updateTimeRemaining = useCallback((expiry: number) => {
        const remaining = Math.max(0, Math.floor((expiry * 1000 - Date.now()) / 1000));
        setTimeRemaining(remaining);
    }, []);

    // Gestion des erreurs
    const handleError = useCallback((err: unknown): AuthError => {
        if (err instanceof Error) {
            // Erreur réseau
            if (err.name === 'TypeError' || err.message.includes('fetch')) {
                return {
                    code: ERROR_CODES.NETWORK_ERROR,
                    message: 'Network error. Please check your connection.',
                };
            }

            // Erreur d'authentification
            try {
                const errorData = JSON.parse(err.message);
                if (errorData.error) {
                    return {
                        code: mapErrorCode(errorData.error),
                        message: errorData.error,
                        details: errorData.details,
                    };
                }
            } catch {
                // Pas du JSON, utiliser le message directement
            }

            return {
                code: ERROR_CODES.UNKNOWN_ERROR,
                message: err.message,
            };
        }

        return {
            code: ERROR_CODES.UNKNOWN_ERROR,
            message: 'An unknown error occurred',
        };
    }, []);

    const mapErrorCode = (errorMessage: string): string => {
        const lowerMessage = errorMessage.toLowerCase();
        if (lowerMessage.includes('credentials') || lowerMessage.includes('invalid')) {
            return ERROR_CODES.INVALID_CREDENTIALS;
        }
        if (lowerMessage.includes('disabled') || lowerMessage.includes('account')) {
            return ERROR_CODES.ACCOUNT_DISABLED;
        }
        if (lowerMessage.includes('expired') || lowerMessage.includes('token')) {
            return ERROR_CODES.TOKEN_EXPIRED;
        }
        if (lowerMessage.includes('validation') || lowerMessage.includes('required')) {
            return ERROR_CODES.VALIDATION_ERROR;
        }
        return ERROR_CODES.UNKNOWN_ERROR;
    };

    const clearError = useCallback(() => {
        setError(null);
    }, []);

    // Connexion
    const login = useCallback(async (email: string, password: string): Promise<boolean> => {
        setIsLoading(true);
        setError(null);

        // Validation basique côté client
        if (!email || !email.includes('@')) {
            setError({
                code: ERROR_CODES.VALIDATION_ERROR,
                message: 'Please enter a valid email address',
            });
            setIsLoading(false);
            return false;
        }

        if (!password || password.length < 1) {
            setError({
                code: ERROR_CODES.VALIDATION_ERROR,
                message: 'Please enter your password',
            });
            setIsLoading(false);
            return false;
        }

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(JSON.stringify({ error: errorData.error || 'Authentication failed' }));
            }

            const data: AuthResponse = await response.json();
            
            // Stocker le token
            setToken(data.token);
            
            // Stocker le refresh token si présent
            if ('refreshToken' in data) {
                setRefreshToken((data as unknown as { refreshToken: string }).refreshToken);
            }

            // Parser et stocker les infos utilisateur
            const payload = parseJwt(data.token);
            if (payload) {
                setUser(payload);
                setTokenState(data.token);
                setIsAuthenticated(true);
                updateTimeRemaining(payload.exp);
                setIsTokenExpiringSoonState(isTokenExpiringSoon(refreshThresholdMinutes));
            }

            setIsLoading(false);
            return true;
        } catch (err) {
            const authError = handleError(err);
            setError(authError);
            setIsLoading(false);
            return false;
        }
    }, [handleError, refreshThresholdMinutes, updateTimeRemaining]);

    // Déconnexion
    const logout = useCallback(() => {
        removeToken();
        setTokenState(null);
        setUser(null);
        setIsAuthenticated(false);
        setIsTokenExpiringSoonState(false);
        setTimeRemaining(0);
        setError(null);
    }, []);

    // Refresh de l'authentification
    const refreshAuth = useCallback(async (): Promise<boolean> => {
        try {
            const refreshTokenValue = getRefreshToken();
            const currentToken = getToken();

            if (!currentToken && !refreshTokenValue) {
                return false;
            }

            const headers: HeadersInit = {
                'Content-Type': 'application/json',
            };

            if (currentToken) {
                headers['Authorization'] = `Bearer ${currentToken}`;
            }

            const response = await fetch('/api/refresh', {
                method: 'POST',
                headers,
            });

            if (!response.ok) {
                if (response.status === 401) {
                    // Token expiré, déconnecter
                    logout();
                    return false;
                }
                throw new Error('Refresh failed');
            }

            const data: AuthResponse = await response.json();
            
            setToken(data.token);
            if ('refreshToken' in data) {
                setRefreshToken((data as unknown as { refreshToken: string }).refreshToken);
            }

            const payload = parseJwt(data.token);
            if (payload) {
                setUser(payload);
                setTokenState(data.token);
                updateTimeRemaining(payload.exp);
            }

            return true;
        } catch (err) {
            console.error('Refresh failed:', err);
            return false;
        }
    }, [logout, updateTimeRemaining]);

    // Vérifier si l'utilisateur a un rôle spécifique
    const hasRole = useCallback((role: string): boolean => {
        if (!user) {
            return false;
        }
        return user.roles.includes(role);
    }, [user]);

    // Récupérer l'email de l'utilisateur
    const userEmail = user?.email || null;
    const userRoles = user?.roles || [];

    const contextValue: AuthContextType = {
        isAuthenticated,
        isLoading,
        user,
        userEmail,
        userRoles,
        token,
        tokenExpiry: user?.exp || null,
        timeRemaining,
        login,
        logout,
        refreshAuth,
        error,
        clearError,
        hasRole,
        isTokenExpiringSoon,
    };

    return (
        <AuthContext.Provider value={contextValue}>
            {children}
        </AuthContext.Provider>
    );
}

// Hook pour utiliser l'authentification
export function useAuth(): AuthContextType {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}

// Hook optionnel pour accéder uniquement à l'état d'authentification
export function useIsAuthenticated(): boolean {
    const { isAuthenticated, isLoading } = useAuth();
    return !isLoading && isAuthenticated;
}

// Hook optionnel pour accéder à l'utilisateur
export function useUser(): JWTPayload | null {
    const { user, isLoading } = useAuth();
    return isLoading ? null : user;
}

// Hook optionnel pour accéder aux rôles
export function useUserRoles(): string[] {
    const { userRoles, isLoading } = useAuth();
    return isLoading ? [] : userRoles;
}

// Composant de formulaire de connexion avec gestion d'erreurs
interface LoginFormProps {
    onSuccess?: () => void;
    onError?: (error: AuthError) => void;
    className?: string;
}

export function LoginForm({ onSuccess, onError, className }: LoginFormProps): JSX.Element {
    const { login, error, isLoading, clearError } = useAuth();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);

    // Effet pour déclencher le callback d'erreur
    useEffect(() => {
        if (error && onError) {
            onError(error);
        }
    }, [error, onError]);

    // Effet pour déclencher le callback de succès après connexion
    useEffect(() => {
        const checkSuccess = async () => {
            const token = getToken();
            if (token && !error) {
                if (onSuccess) {
                    onSuccess();
                }
            }
        };
        checkSuccess();
    }, [error, onSuccess]);

    const handleSubmit = async (e: React.FormEvent): Promise<void> => {
        e.preventDefault();
        clearError();

        const success = await login(email, password);
        if (!success && !error && onError) {
            onError({
                code: ERROR_CODES.UNKNOWN_ERROR,
                message: 'Login failed',
            });
        }
    };

    const inputStyle: React.CSSProperties = {
        width: '100%',
        padding: '12px',
        marginBottom: '15px',
        border: '1px solid #ddd',
        borderRadius: '4px',
        boxSizing: 'border-box',
        fontSize: '16px',
    };

    const buttonStyle: React.CSSProperties = {
        width: '100%',
        padding: '12px',
        backgroundColor: '#0d6efd',
        color: 'white',
        border: 'none',
        borderRadius: '4px',
        cursor: isLoading ? 'not-allowed' : 'pointer',
        opacity: isLoading ? 0.7 : 1,
        fontSize: '16px',
        fontWeight: '500',
    };

    return (
        <form onSubmit={handleSubmit} className={className} style={{ maxWidth: '400px', margin: '0 auto' }}>
            <h2 style={{ marginBottom: '20px', textAlign: 'center' }}>Connexion</h2>

            {error && (
                <div
                    role="alert"
                    style={{
                        padding: '12px',
                        marginBottom: '15px',
                        backgroundColor: '#f8d7da',
                        borderColor: '#f5c2c7',
                        color: '#842029',
                        borderRadius: '4px',
                        fontSize: '14px',
                    }}
                >
                    {error.message}
                </div>
            )}

            <div style={{ marginBottom: '15px' }}>
                <label htmlFor="email" style={{ display: 'block', marginBottom: '5px', fontWeight: '500' }}>
                    Email
                </label>
                <input
                    type="email"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    disabled={isLoading}
                    style={inputStyle}
                    autoComplete="email"
                    placeholder="votre@email.com"
                />
            </div>

            <div style={{ marginBottom: '20px' }}>
                <label htmlFor="password" style={{ display: 'block', marginBottom: '5px', fontWeight: '500' }}>
                    Mot de passe
                </label>
                <div style={{ position: 'relative' }}>
                    <input
                        type={showPassword ? 'text' : 'password'}
                        id="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        disabled={isLoading}
                        style={{ ...inputStyle, paddingRight: '40px' }}
                        autoComplete="current-password"
                        placeholder="••••••••"
                    />
                    <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{
                            position: 'absolute',
                            right: '10px',
                            top: '50%',
                            transform: 'translateY(-50%)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            color: '#666',
                            fontSize: '14px',
                        }}
                    >
                        {showPassword ? 'Masquer' : 'Afficher'}
                    </button>
                </div>
            </div>

            <button type="submit" disabled={isLoading} style={buttonStyle}>
                {isLoading ? (
                    <span>
                        <span style={{ marginRight: '8px' }}>⏳</span>
                        Connexion en cours...
                    </span>
                ) : (
                    'Se connecter'
                )}
            </button>

            <p style={{ marginTop: '15px', textAlign: 'center', fontSize: '14px', color: '#666' }}>
                Pas encore de compte ?{' '}
                <a href="/register" style={{ color: '#0d6efd' }}>
                    S'inscrire
                </a>
            </p>
        </form>
    );
}
