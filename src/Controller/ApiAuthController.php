<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\Persistence\ManagerRegistry;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

#[Route('/api', name: 'api_')]
class ApiAuthController extends AbstractController
{
    public function __construct(
        private readonly ManagerRegistry $managerRegistry,
        private readonly ValidatorInterface $validator
    ) {
    }

    #[Route('/login', name: 'login', methods: ['POST'])]
    public function login(
        Request $request,
        JWTTokenManagerInterface $jwtManager,
        UserPasswordHasherInterface $passwordHasher
    ): JsonResponse {
        $data = $this->getJsonData($request);

        // Validation des données requises
        $validationError = $this->validateLoginData($data);
        if ($validationError !== null) {
            return $validationError;
        }

        // Récupérer l'utilisateur de manière sécurisée
        $user = $this->managerRegistry->getRepository(User::class)->findOneBy(['email' => $data['email']]);

        // Ne pas révéler si l'utilisateur existe ou non pour des raisons de sécurité
        if ($user === null || !$this->verifyPassword($user, $data['password'], $passwordHasher)) {
            return new JsonResponse(
                ['error' => 'Invalid credentials'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        // Vérifier que l'utilisateur n'est pas désactivé
        if ($user instanceof User && method_exists($user, 'isDisabled') && $user->isDisabled()) {
            return new JsonResponse(
                ['error' => 'Account is disabled'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        // Générer le token JWT
        $token = $jwtManager->create($user);

        return new JsonResponse([
            'token' => $token,
            'user' => $this->serializeUser($user),
        ], Response::HTTP_OK);
    }

    #[Route('/register', name: 'register', methods: ['POST'])]
    public function register(
        Request $request,
        UserPasswordHasherInterface $passwordHasher,
        CsrfTokenManagerInterface $csrfTokenManager
    ): JsonResponse {
        $data = $this->getJsonData($request);

        // Validation CSRF (protection contre les attaques CSRF)
        $csrfTokenValue = $data['_csrf_token'] ?? null;
        if ($csrfTokenValue === null || !$csrfTokenManager->isTokenValid(new CsrfToken('register', $csrfTokenValue))) {
            return new JsonResponse(
                ['error' => 'Invalid CSRF token'],
                Response::HTTP_BAD_REQUEST
            );
        }

        // Validation des données requises
        $validationError = $this->validateRegisterData($data);
        if ($validationError !== null) {
            return $validationError;
        }

        $userRepository = $this->managerRegistry->getRepository(User::class);

        // Vérifier si l'email existe déjà
        $existingUser = $userRepository->findOneBy(['email' => $data['email']]);
        if ($existingUser !== null) {
            return new JsonResponse(
                ['error' => 'Email already exists'],
                Response::HTTP_CONFLICT
            );
        }

        // Créer le nouvel utilisateur
        $user = new User();
        $user->setEmail($data['email']);
        $user->setPassword($passwordHasher->hashPassword($user, $data['password']));
        $user->setRoles(['ROLE_USER']);

        // Valider l'utilisateur avec les contraintes d'entité
        $errors = $this->validator->validate($user);
        if (count($errors) > 0) {
            $errorMessages = [];
            foreach ($errors as $error) {
                $errorMessages[$error->getPropertyPath()] = $error->getMessage();
            }

            return new JsonResponse(
                ['error' => 'Validation failed', 'errors' => $errorMessages],
                Response::HTTP_BAD_REQUEST
            );
        }

        // Sauvegarder l'utilisateur
        $entityManager = $this->managerRegistry->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return new JsonResponse([
            'message' => 'User created successfully',
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getEmail(),
            ],
        ], Response::HTTP_CREATED);
    }

    #[Route('/profile', name: 'profile', methods: ['GET'])]
    public function profile(): JsonResponse
    {
        $user = $this->getUser();

        if (!$user instanceof User) {
            return new JsonResponse(
                ['error' => 'Not authenticated'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        return new JsonResponse($this->serializeUser($user), Response::HTTP_OK);
    }

    #[Route('/refresh', name: 'refresh', methods: ['POST'])]
    public function refresh(Request $request, JWTTokenManagerInterface $jwtManager): JsonResponse
    {
        $user = $this->getUser();

        if (!$user instanceof User) {
            return new JsonResponse(
                ['error' => 'Not authenticated'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        // Générer un nouveau token
        $token = $jwtManager->create($user);

        return new JsonResponse([
            'token' => $token,
            'user' => $this->serializeUser($user),
        ], Response::HTTP_OK);
    }

    /**
     * Extrait les données JSON de la requête
     */
    private function getJsonData(Request $request): array
    {
        $content = $request->getContent();
        
        if (empty($content)) {
            return [];
        }

        $data = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return [];
        }

        return $data;
    }

    /**
     * Valide les données de connexion
     */
    private function validateLoginData(array $data): ?JsonResponse
    {
        if (!isset($data['email']) || !isset($data['password'])) {
            return new JsonResponse(
                ['error' => 'Email and password are required'],
                Response::HTTP_BAD_REQUEST
            );
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return new JsonResponse(
                ['error' => 'Invalid email format'],
                Response::HTTP_BAD_REQUEST
            );
        }

        return null;
    }

    /**
     * Valide les données d'inscription
     */
    private function validateRegisterData(array $data): ?JsonResponse
    {
        if (!isset($data['email']) || !isset($data['password'])) {
            return new JsonResponse(
                ['error' => 'Email and password are required'],
                Response::HTTP_BAD_REQUEST
            );
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return new JsonResponse(
                ['error' => 'Invalid email format'],
                Response::HTTP_BAD_REQUEST
            );
        }

        if (strlen($data['password']) < 8) {
            return new JsonResponse(
                ['error' => 'Password must be at least 8 characters long'],
                Response::HTTP_BAD_REQUEST
            );
        }

        // Vérifier la complexité du mot de passe (au moins une majuscule, une minuscule et un chiffre)
        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/', $data['password'])) {
            return new JsonResponse(
                ['error' => 'Password must contain at least one uppercase letter, one lowercase letter, and one digit'],
                Response::HTTP_BAD_REQUEST
            );
        }

        return null;
    }

    /**
     * Vérifie le mot de passe de manière sécurisée (évite les timing attacks)
     */
    private function verifyPassword(User $user, string $password, UserPasswordHasherInterface $hasher): bool
    {
        // Utiliser la méthode sécurisée de Symfony
        return $hasher->isPasswordValid($user, $password);
    }

    /**
     * Sérialise les données de l'utilisateur pour la réponse
     */
    private function serializeUser(User $user): array
    {
        return [
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
        ];
    }
}
