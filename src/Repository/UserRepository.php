<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;

/**
 * Repository pour l'entité User.
 * 
 * Ce repository fournit des méthodes personnalisées pour interroger
 * les utilisateurs et gérer les opérations de base de données.
 * 
 * @extends ServiceEntityRepository<User>
 * 
 * @package App\Repository
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    /**
     * Constructeur du repository.
     */
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Trouve un utilisateur par son email.
     *
     * @param string $email L'email à rechercher
     * @return User|null L'utilisateur trouvé ou null
     */
    public function findOneByEmail(string $email): ?User
    {
        return $this->findOneBy(['email' => $email]);
    }

    /**
     * Trouve tous les utilisateurs actifs.
     *
     * @return User[] Tableau des utilisateurs actifs
     */
    public function findActiveUsers(): array
    {
        return $this->findBy(['isActive' => true]);
    }

    /**
     * Trouve tous les utilisateurs ayant un rôle spécifique.
     *
     * @param string $role Le rôle à rechercher
     * @return User[] Tableau des utilisateurs avec ce rôle
     */
    public function findByRole(string $role): array
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.roles LIKE :role')
            ->setParameter('role', '%"' . $role . '"%')
            ->getQuery()
            ->getResult();
    }

    /**
     * Vérifie si un email existe déjà.
     *
     * @param string $email L'email à vérifier
     * @return bool True si l'email existe
     */
    public function emailExists(string $email): bool
    {
        return (bool) $this->createQueryBuilder('u')
            ->select('COUNT(u.id)')
            ->andWhere('u.email = :email')
            ->setParameter('email', $email)
            ->getQuery()
            ->getSingleScalarResult() > 0;
    }

    /**
     * Trouve les utilisateurs créés après une date donnée.
     *
     * @param \DateTimeInterface $date La date de référence
     * @return User[] Tableau des utilisateurs créés après cette date
     */
    public function findCreatedAfter(\DateTimeInterface $date): array
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.createdAt > :date')
            ->setParameter('date', $date)
            ->orderBy('u.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * Trouve les utilisateurs inactifs (non connectés depuis une date donnée).
     *
     * @param \DateTimeInterface $since La date de référence
     * @return User[] Tableau des utilisateurs inactifs
     */
    public function findInactiveSince(\DateTimeInterface $since): array
    {
        // Note: Cette méthode nécessiterait un champ lastLogin
        // Pour l'instant, retourne les utilisateurs non actifs
        return $this->findBy(['isActive' => false]);
    }

    /**
     * Met à jour le mot de passe d'un utilisateur.
     * Implémentation de l'interface PasswordUpgraderInterface.
     *
     * @param PasswordAuthenticatedUserInterface $user L'utilisateur
     * @param string $newHashedPassword Le nouveau mot de passe hashé
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(
                sprintf('Instances of "%s" are not supported.', $user::class)
            );
        }

        $user->setPassword($newHashedPassword);
        $user->setUpdatedAt(new \DateTimeImmutable());
        
        $this->getEntityManager()->persist($user);
        $this->getEntityManager()->flush();
    }

    /**
     * Sauvegarde un utilisateur (création ou mise à jour).
     *
     * @param User $user L'utilisateur à sauvegarder
     * @param bool $flush Si true, synchronise avec la base de données
     * @return User L'utilisateur sauvegardé
     */
    public function save(User $user, bool $flush = true): User
    {
        $user->setUpdatedAt(new \DateTimeImmutable());
        
        $this->getEntityManager()->persist($user);
        
        if ($flush) {
            $this->getEntityManager()->flush();
        }
        
        return $user;
    }

    /**
     * Supprime un utilisateur.
     *
     * @param User $user L'utilisateur à supprimer
     * @param bool $flush Si true, synchronise avec la base de données
     */
    public function remove(User $user, bool $flush = true): void
    {
        $this->getEntityManager()->remove($user);
        
        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    /**
     * Compte le nombre total d'utilisateurs.
     *
     * @return int Le nombre d'utilisateurs
     */
    public function countUsers(): int
    {
        return (int) $this->createQueryBuilder('u')
            ->select('COUNT(u.id)')
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * Recherche des utilisateurs par terme (email ou roles).
     *
     * @param string $term Le terme de recherche
     * @param int $limit Le nombre maximum de résultats
     * @return User[] Tableau des utilisateurs correspondants
     */
    public function searchByTerm(string $term, int $limit = 10): array
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.email LIKE :term OR u.roles LIKE :term')
            ->setParameter('term', '%' . $term . '%')
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();
    }

    /**
     * Trouve les utilisateurs paginés.
     *
     * @param int $page Le numéro de page (1-indexed)
     * @param int $limit Le nombre d'utilisateurs par page
     * @return User[] Tableau des utilisateurs de la page
     */
    public function findByPage(int $page, int $limit = 20): array
    {
        $firstResult = ($page - 1) * $limit;
        
        return $this->createQueryBuilder('u')
            ->orderBy('u.createdAt', 'DESC')
            ->setFirstResult($firstResult)
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();
    }
}
