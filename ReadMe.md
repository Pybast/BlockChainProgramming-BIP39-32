# Blockchain Programming - HD Wallet programming

• Créer un repo github et le partager avec le prof
• Créer un programme python ou JS interactif en ligne de commande (2pts)
• Créer un entier aléatoire pouvant servir de seed
à un wallet de façon sécurisée (2 pts)
• Représenter cette seed en binaire et le découper en lot de 11 bits (2 pts)
• Attribuer à chaque lot un mot selon la liste BIP 39 et afficher la seed en mnémonique (2 pts)
• Permettre l’import d’une seed mnémonique (2 pts)
• Vérifiez les clés que vous générez sur https://iancoleman.io/bip39/
• Extraire la master private key et le chain code (2 pts)
• Extraire la master public key (2 pts) • Générer un clé enfant 2 pts) 
• Générer une clé enfant à l’index N (2pts)
• Générer une clé enfant à l’index N au niveau de dérivation M(2 pts)

---
## Requirements

For development, you will only need Node.js and a node global package, yarn, installed in your environement.

### Node
- #### Node installation on Windows

  Just go on [official Node.js website](https://nodejs.org/) and download the installer.
Also, be sure to have `git` available in your PATH, `npm` might need it (You can find git [here](https://git-scm.com/)).

- #### Node installation on Ubuntu

  You can install nodejs and npm easily with apt install, just run the following commands.

      $ sudo apt install nodejs
      $ sudo apt install npm

- #### Other Operating Systems
  You can find more information about the installation on the [official Node.js website](https://nodejs.org/) and the [official NPM website](https://npmjs.org/).

If the installation was successful, you should be able to run the following command.

    $ node --version
    v8.11.3

    $ npm --version
    6.1.0

If you need to update `npm`, you can make it using `npm`! Cool right? After running the following command, just open again the command line and be happy.

    $ npm install npm -g

###
### Yarn installation
  After installing node, this project will need yarn too, so just run the following command.

      $ npm install -g yarn

---

## Install

    $ git clone  https://github.com/Pibastte/BlockChainProgramming-BIP39-32.git
    $ cd BlockChainProgramming-BIP39-32
    $ yarn install

## Running the project

    $ yarn go