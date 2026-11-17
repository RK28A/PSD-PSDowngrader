# Tests

## Automatiques
`./tests/run.sh` compile `build/tests.exe`, démarre un serveur HTTPS local (`tests/server.py`) et lance les tests sous Wine. GitHub Actions les exécute à chaque build.

Couvert : extraction des archives (y compris mise en page modifiée), politique d'URL et de redirections, en-tête SLB2, cache vérifié, copie (succès, SHA-256 incorrect, annulation, clé pleine, clé retirée, protection en écriture, changement d'identité, restauration de l'ancien PUP, cache corrompu), téléchargement (coupures multiples, ETag modifié, redirection piège, 404, page HTML, SHA-256 incorrect).

## Manuels (matériel réel)
| # | Scénario | Attendu |
|---|---|---|
| 1 | Débrancher la clé pendant la copie | « La clé a été retirée », aucun `.tmp` restant après rebranchement |
| 2 | Clé presque pleine (< 1,3 Gio libres) | Refus avant copie ; si un ancien PUP libère la place, sauvegarde sur le PC puis restauration en cas d'échec |
| 3 | Clés FAT32, exFAT, NTFS, RAW | FAT32/exFAT acceptées ; NTFS/RAW proposent le formatage |
| 4 | Formatage puis vérification | Clé en exFAT, nommée PS5 ; refus si la lettre change pendant la demande UAC |
| 5 | Clé avec verrou d'écriture | Message « protégée en écriture », aucune écriture tentée |
| 6 | Téléchargement HTTPS coupé (Wi-Fi off/on) | Reprise automatique |
| 7 | MEGA avec MEGAcmd, puis Annuler | Transfert arrêté (`mega-transfers` vide) |
| 8 | Annuler à chaque étape | État propre, téléchargement partiel proposé à la conservation |
| 9 | Windows 10 et Windows 11 | Coins arrondis, icônes, DPI 100/125/150/200 % |
| 10 | Plusieurs marques et capacités (8 à 256 Go) | Détection, relecture directe ou de secours |
| 11 | Fermer pendant une opération | Arrêt propre ; refus pendant un formatage |
