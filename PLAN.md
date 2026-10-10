# ZFlip — wallet Zcash shielded sur Flipper Zero

Le Flipper garde la clé et signe, l'iPhone fait tout le reste (synchronisation, preuves, envoi).
Ils se parlent en Bluetooth.

## Les 3 morceaux

| Dossier | Quoi | Langage |
|---|---|---|
| `core/` | Le cœur crypto : seed, adresses shielded, vérification et signature des transactions. Testé sur Mac. | Rust (sans OS) |
| `flipper/` | L'app Flipper : écrans, QR animé, coffre chiffré, Bluetooth. | Rust (flipperzero-rs) |
| `ios/` | L'app iPhone : solde, envoi, réception, appairage avec le Flipper. | Swift / SwiftUI |

Le protocole Bluetooth entre les deux est décrit dans `PROTOCOL.md`.

## Comment marche un envoi

1. L'iPhone (qui n'a que la **clé de visualisation**) prépare la transaction et calcule la preuve zk.
2. Il l'envoie au Flipper en Bluetooth.
3. Le Flipper **vérifie lui-même** : à qui va l'argent, combien, les frais, et que la monnaie rendue revient bien chez toi.
4. Il affiche « Envoyer 2 ZEC à u1abc… ? ». Tu valides avec le bouton.
5. Il signe et renvoie la signature. L'iPhone diffuse la transaction.

Même si l'iPhone est piraté, il ne peut rien dépenser sans que tu aies vu et validé le vrai montant
et la vraie adresse sur l'écran du Flipper.

## Sécurité

- La seed (24 mots) est créée sur le Flipper avec son générateur aléatoire matériel et ne sort jamais.
- Elle est chiffrée deux fois sur la carte SD : avec ton code PIN et avec la clé unique de la puce du
  Flipper (gardée dans sa zone sécurisée). Voler la carte SD seule ne sert à rien.
- 10 mauvais codes → le coffre s'efface (la seed papier permet de tout récupérer).
- Bluetooth : appairage avec un code à 6 chiffres affiché sur le Flipper, et chaque connexion
  doit être acceptée sur le Flipper.
- Limite honnête : le Flipper n'a pas de puce sécurisée comme un Ledger. Pour des montants
  « de poche », et la seed papier reste la vraie sauvegarde.

## Pools

- Adresses : Orchard (adresse unifiée `u1…`). Ironwood (le pool actif depuis NU6.3, juillet 2026)
  utilise les mêmes adresses.
- Signature : Orchard et Ironwood. Pas de transparent ni de Sapling en v1 (refusé proprement).

## Étapes

1. **Cœur crypto** : seed, adresses, clé de visualisation, vérification + signature PCZT,
   testé contre les bibliothèques officielles Zcash.
2. **App Flipper** : création/restauration de seed, PIN, adresses + QR animé (forge du bouclier),
   Bluetooth, écran de validation.
3. **App iPhone** : appairage, import de la clé de visualisation, solde, recevoir, envoyer.
4. Tests sur testnet avec de faux ZEC, puis petits montants réels.

## Ce dont j'ai besoin de toi

- Plus tard seulement : brancher ton Flipper pour installer l'app (et me dire sa version de firmware),
  et ton iPhone pour installer l'app iOS.
