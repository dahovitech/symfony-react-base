<?php

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * Entité User représentant un utilisateur de l'application.
 * 
 * Cette entité implémente les interfaces UserInterface et PasswordAuthenticatedUserInterface
 * pour une intégration complète avec le système de sécurité de Symfony.
 * 
 * @package App\Entity
 */
#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: '`user`')]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
#[UniqueEntity(
    fields: ['email'],
    message: 'There is already an account with this email',
    groups: ['Registration', 'Default']
)]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    /**
     * Identifiant unique de l'utilisateur.
     */
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    /**
     * Adresse email de l'utilisateur.
     * Doit être unique et valider comme email.
     */
    #[ORM\Column(type: 'string', length: 180)]
    #[Assert\NotBlank(message: 'Email cannot be blank', groups: ['Registration', 'Default'])]
    #[Assert\Email(message: 'The email {{ value }} is not a valid email', groups: ['Registration', 'Default'])]
    #[Assert\Length(
        max: 180,
        maxMessage: 'Email cannot be longer than {{ limit }} characters',
        groups: ['Registration', 'Default']
    )]
    private string $email;

    /**
     * Rôles de l'utilisateur.
     * Stocké sous forme de tableau JSON en base de données.
     */
    #[ORM\Column(type: 'json')]
    #[Assert\Type(type: 'array', message: 'Roles must be an array', groups: ['Default'])]
    private array $roles = [];

    /**
     * Mot de passe hashé de l'utilisateur.
     */
    #[ORM\Column(type: 'string')]
    #[Assert\NotBlank(message: 'Password cannot be blank', groups: ['Registration'])]
    #[Assert\Length(
        min: 8,
        max: 255,
        minMessage: 'Password must be at least {{ limit }} characters long',
        maxMessage: 'Password cannot be longer than {{ limit }} characters',
        groups: ['Registration']
    )]
    private string $password;

    /**
     * Flag indiquant si le compte est activé ou désactivé.
     */
    #[ORM\Column(type: 'boolean', options: ['default' => true])]
    private bool $isActive = true;

    /**
     * Date de création du compte.
     */
    #[ORM\Column(type: 'datetime_immutable', options: ['default' => 'CURRENT_TIMESTAMP'])]
    private \DateTimeImmutable $createdAt;

    /**
     * Date de dernière modification du compte.
     */
    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $updatedAt = null;

    /**
     * Constructeur de l'entité User.
     * Initialise les dates et le rôle par défaut.
     */
    public function __construct()
    {
        $this->roles = ['ROLE_USER'];
        $this->createdAt = new \DateTimeImmutable();
    }

    /**
     * Récupère l'identifiant de l'utilisateur.
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * Récupère l'email de l'utilisateur.
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }

    /**
     * Définit l'email de l'utilisateur.
     */
    public function setEmail(string $email): self
    {
        $this->email = $email;
        $this->updatedAt = new \DateTimeImmutable();
        return $this;
    }

    /**
     * Récupère l'identifiant unique de l'utilisateur pour le système de sécurité.
     * C'est cette méthode qui est utilisée pour l'authentification.
     */
    public function getUserIdentifier(): string
    {
        return $this->email;
    }

    /**
     * Récupère les rôles de l'utilisateur.
     * Garantit que chaque utilisateur a au moins ROLE_USER.
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // Garantir que chaque utilisateur a au moins ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_values(array_unique($roles));
    }

    /**
     * Définit les rôles de l'utilisateur.
     */
    public function setRoles(array $roles): self
    {
        $this->roles = $roles;
        $this->updatedAt = new \DateTimeImmutable();
        return $this;
    }

    /**
     * Ajoute un rôle à l'utilisateur.
     */
    public function addRole(string $role): self
    {
        if (!in_array($role, $this->roles, true)) {
            $this->roles[] = $role;
            $this->updatedAt = new \DateTimeImmutable();
        }
        return $this;
    }

    /**
     * Retire un rôle à l'utilisateur.
     */
    public function removeRole(string $role): self
    {
        $this->roles = array_values(array_filter($this->roles, fn($r) => $r !== $role));
        $this->updatedAt = new \DateTimeImmutable();
        return $this;
    }

    /**
     * Récupère le mot de passe hashé.
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Définit le mot de passe hashé.
     */
    public function setPassword(string $password): self
    {
        $this->password = $password;
        $this->updatedAt = new \DateTimeImmutable();
        return $this;
    }

    /**
     * Vérifie si le mot de passe brut correspond au mot de passe hashé.
     * Méthode utilitaire pour les tests.
     */
    public function validatePassword(string $plainPassword, string $hashedPassword): bool
    {
        return password_verify($plainPassword, $hashedPassword);
    }

    /**
     * Cette méthode est appelée pour effacer les données sensibles.
     * Utile pour nettoyer les mots de passe en clair après l'authentification.
     */
    public function eraseCredentials(): void
    {
        // Si vous stockez des données temporaires sensibles, nettoyez-les ici
        // Ex: $this->plainPassword = null;
    }

    /**
     * Vérifie si le compte est actif.
     */
    public function isActive(): bool
    {
        return $this->isActive;
    }

    /**
     * Active ou désactive le compte.
     */
    public function setIsActive(bool $isActive): self
    {
        $this->isActive = $isActive;
        $this->updatedAt = new \DateTimeImmutable();
        return $this;
    }

    /**
     * Désactive le compte.
     */
    public function disable(): self
    {
        return $this->setIsActive(false);
    }

    /**
     * Active le compte.
     */
    public function enable(): self
    {
        return $this->setIsActive(true);
    }

    /**
     * Récupère la date de création du compte.
     */
    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    /**
     * Définit la date de création (principalement pour les fixtures).
     */
    public function setCreatedAt(\DateTimeImmutable $createdAt): self
    {
        $this->createdAt = $createdAt;
        return $this;
    }

    /**
     * Récupère la date de dernière modification.
     */
    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        return $this->updatedAt;
    }

    /**
     * Définit la date de dernière modification.
     */
    public function setUpdatedAt(?\DateTimeImmutable $updatedAt): self
    {
        $this->updatedAt = $updatedAt;
        return $this;
    }

    /**
     * Met à jour la date de modification.
     */
    public function touch(): self
    {
        $this->updatedAt = new \DateTimeImmutable();
        return $this;
    }

    /**
     * Représentation textuelle de l'utilisateur.
     */
    public function __toString(): string
    {
        return $this->email ?? 'User (id: ' . $this->id . ')';
    }
}
