/*
 -----------------------------------------------------------------------------------
 Laboratoire : 02
 Fichier     : main.cpp
 Auteurs     : Muaremi Dejvid
               
 Date        : 15.04.2019

 But         : 

 Remarque(s) : 

 Compilateur : 
 -----------------------------------------------------------------------------------
 */

#include <sodium.h>
#include <string.h>
#include <limits>

#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <cstring>

#include "base64.h"

using namespace std;


int hashMasterPassword(char * hash, const char * const password);
int checkMasterPassword(const char * const hash, const char * const password);
int KDF(unsigned char * key, const char * const password, const unsigned char * const salt);
void encryptPassword(unsigned char * cipher, unsigned char * key, unsigned char * nonce, unsigned char * message);
int decryptPassword(unsigned char * decrypted, unsigned char * cipher, unsigned char * key, unsigned char * nonce);

int identityCheck(char* masterPassword, FILE* masterFile);
void newMaster(char* masterPassword, FILE * masterFile, char * hashed_password, unsigned char* salt, const char* const master_password_filename, const char* const site_filename, const char* const password_filename, const char* const nonce_filename);



const char* MASTER_PASSWORD_FILENAME = "master.txt";
const char* SITE_FILENAME = "site.txt";
const char* PASSWORD_FILENAME = "passwords.txt";
const char* NONCE_FILENAME = "nonces.txt";

const size_t MASTER_PASSWORD_LENGTH = 64;
const size_t PASSWORD_LENGTH = 64;
bool start = true;

enum STATES {
    LOCKED, UNLOCKED, QUIT
};

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        cout << "panic! the library couldn't be initialized, it is not safe to use" << endl;
        return 1;
    }
    STATES state = LOCKED;


    char hashed_password[crypto_pwhash_STRBYTES];
    unsigned char * key;
    unsigned char salt[crypto_pwhash_SALTBYTES];

    while (state != QUIT) {
        while (state == LOCKED) {
            cout << "The app is now locked !" << endl;

            FILE* masterFile = fopen(MASTER_PASSWORD_FILENAME, "r+"); // NULL if there's no file.
            char* masterPassword = (char*) sodium_malloc(MASTER_PASSWORD_LENGTH + 1);
            if (masterPassword == NULL) {
                return EXIT_FAILURE;
            }
            if (masterFile == NULL) {
                // Create the files
                newMaster(masterPassword, masterFile, hashed_password, salt, MASTER_PASSWORD_FILENAME, SITE_FILENAME, PASSWORD_FILENAME, NONCE_FILENAME);

            } else {
                if (identityCheck(masterPassword, masterFile)) {
                    cout << "Who are you, this is not the password !?" << endl;
                    sodium_free(masterPassword);
                    continue;
                }
            }

            // It's way easier to read it like a stream from now.
            fstream masterStream;
            masterStream.open(MASTER_PASSWORD_FILENAME);
            string stored_salt;
            getline(masterStream, stored_salt); // Get rid of the hash
            getline(masterStream, stored_salt); // Get the salt
            masterStream.close(); // useless but it's a good practice to do it.
            stored_salt = base64_decode(stored_salt);

            key = (unsigned char*) sodium_malloc(crypto_secretbox_KEYBYTES);
            if (KDF(key, masterPassword, (unsigned char*) stored_salt.c_str())) {
                sodium_free(masterPassword);
                return EXIT_FAILURE;
            }
            // Get out of my memory, plaintext !
            sodium_free(masterPassword);

            // Unlock the app.
            state = UNLOCKED;
        }

        while (state == UNLOCKED) {
            cout << "The app is now unlocked !" << endl;
            int choice;
            fstream siteFile;
            fstream passwordFile;
            fstream nonceFile;

            cout << "***************************************" << endl;
            cout << " 1 - Recover a password." << endl;
            cout << " 2 - Store a password." << endl;
            cout << " 3 - Change master password." << endl;
            cout << " 4 - Lock the manager." << endl;
            cout << " 0 - Quit the manager." << endl;
            cout << " Enter your choice and press return: ";

            cin >> choice;

            switch (choice) {
                case 0:
                {
                    sodium_free(key);
                    state = QUIT;
                    break;
                }
                case 1:
                {
                    int p_choice;

                    do {
                        size_t l = 1, p = 0;
                        string line;
                        cout << "***************************************" << endl;
                        siteFile.open(SITE_FILENAME);
                        while (getline(siteFile, line)) {
                            cout << l++ << " - " << line << endl;
                        }
                        cout << "0 - leave." << endl;
                        siteFile.close();

                        cout << "Enter your choice and press return: ";
                        cin >> p_choice;
                        if (!cin.fail()) {
                            cin.clear();
                            cin.ignore(numeric_limits<streamsize>::max(), '\n');
                        }
                        if (p_choice >= l) {
                            cout << "bad index." << endl;
                            continue;
                        }
                        if (p_choice == 0) {
                            continue;
                        }

                        // We have to find it now.
                        siteFile.open(SITE_FILENAME);
                        passwordFile.open(PASSWORD_FILENAME);
                        nonceFile.open(NONCE_FILENAME);
                        string site;
                        string cipher;
                        string nonce;
                        while (p < p_choice) {
                            getline(siteFile, site);
                            getline(passwordFile, cipher);
                            getline(nonceFile, nonce);
                            p++;
                        }
                        siteFile.close();
                        passwordFile.close();
                        nonceFile.close();

                        cipher = base64_decode(cipher);
                        nonce = base64_decode(nonce);
                        unsigned char* decrypted = (unsigned char*) sodium_malloc(PASSWORD_LENGTH + 1);
                        if (decrypted == NULL) {
                            return EXIT_FAILURE;
                        }
                        decrypted[cipher.size() - crypto_secretbox_MACBYTES] = '\0';

                        if (decryptPassword(decrypted, (unsigned char*) cipher.c_str(), key, (unsigned char*) nonce.c_str())) {
                            cout << "I may have lost this password..." << endl;
                            sodium_free(decrypted);
                            continue;
                        }

                        cout << "the password for " << site << " is " << decrypted << endl;
                        sodium_free(decrypted);

                    } while (p_choice != 0);
                    break;
                }
                case 2:
                {
                    string site;
                    unsigned char* password = (unsigned char*) sodium_malloc(PASSWORD_LENGTH + 1);
                    if (password == NULL) {
                        cout << "Sorry but I can't malloc now..." << endl;
                        continue;
                    }
                    unsigned char nonce[crypto_secretbox_NONCEBYTES];
                    // Optain the data.
                    cout << "Choose your site and press return: ";
                    cin >> site;
                    cout << "Choose your password (max : " << PASSWORD_LENGTH << ") and press return: ";
                    cin >> password; // please don't crash...
                    //fgets(password, PASSWORD_LENGTH, stdin);

                    // Encrypt the password and release the memory.
                    unsigned char cipher[crypto_secretbox_MACBYTES + strlen((char*) password)];
                    encryptPassword(cipher, key, nonce, password);
                    sodium_free(password);

                    siteFile.open(SITE_FILENAME, ios::app);
                    siteFile << site << endl;
                    siteFile.close();

                    passwordFile.open(PASSWORD_FILENAME, ios::app);
                    passwordFile << base64_encode(cipher, sizeof (cipher)) << endl;
                    passwordFile.close();

                    nonceFile.open(NONCE_FILENAME, ios::app);
                    nonceFile << base64_encode(nonce, sizeof (nonce)) << endl;
                    nonceFile.close();

                    break;
                }
                case 3:
                {
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');

                    // Can you do this ?
                    FILE* oldMasterFile = fopen(MASTER_PASSWORD_FILENAME, "r+"); // NULL if there's no file.
                    char* oldMasterPassword = (char*) sodium_malloc(MASTER_PASSWORD_LENGTH + 1);
                    if (oldMasterPassword == NULL) {
                        return EXIT_FAILURE;
                    }

                    if (identityCheck(oldMasterPassword, oldMasterFile)) {
                        cout << "Who are you, this is not the password !?" << endl;
                        sodium_free(oldMasterPassword);
                        state = LOCKED;
                        continue;
                    }
                    sodium_free(oldMasterPassword);


                    // Prepare the new values.
                    FILE* tmp_masterFile;
                    char* tmp_masterPassword = (char*) sodium_malloc(MASTER_PASSWORD_LENGTH + 1);
                    if (tmp_masterPassword == NULL) {
                        return EXIT_FAILURE;
                    }
                    const char * tmp_master_filename = "tmp_master.txt";
                    const char * tmp_site_filename = "tmp_site.txt";
                    const char * tmp_password_filename = "tmp_password.txt";
                    const char * tmp_nonce_filename = "tmp_nonce.txt";

                    char tmp_hashed_password[crypto_pwhash_STRBYTES];
                    unsigned char * new_key = (unsigned char*) sodium_malloc(crypto_secretbox_KEYBYTES);
                    unsigned char tmp_salt[crypto_pwhash_SALTBYTES];

                    newMaster(tmp_masterPassword, tmp_masterFile, tmp_hashed_password, tmp_salt, tmp_master_filename, tmp_site_filename, tmp_password_filename, tmp_nonce_filename);

                    if (KDF(new_key, tmp_masterPassword, tmp_salt)) {
                        sodium_free(tmp_masterPassword);
                        return EXIT_FAILURE;
                    }
                    // Get out of my memory, plaintext !
                    sodium_free(tmp_masterPassword);
                    
                    // Parse, decrypt and encrypt the passwords.
                    fstream old_siteFile;
                    fstream old_passwordFile;
                    fstream old_nonceFile;
                    fstream new_siteFile;
                    fstream new_passwordFile;
                    fstream new_nonceFile;

                    old_siteFile.open(SITE_FILENAME);
                    old_passwordFile.open(PASSWORD_FILENAME);
                    old_nonceFile.open(NONCE_FILENAME);

                    string old_site;
                    string old_cipher;
                    string old_nonce;

                    while (getline(old_siteFile, old_site) && getline(old_passwordFile, old_cipher) && getline(old_nonceFile, old_nonce)) {
                        old_cipher = base64_decode(old_cipher);
                        old_nonce = base64_decode(old_nonce);

                        // Decrypt the passwords
                        unsigned char* decrypted = (unsigned char*) sodium_malloc(PASSWORD_LENGTH + 1);
                        if (decrypted == NULL) {
                            return EXIT_FAILURE;
                        }
                        decrypted[old_cipher.size() - crypto_secretbox_MACBYTES] = '\0';
                        // Some password may be lost...


                        if (decryptPassword(decrypted, (unsigned char*) old_cipher.c_str(), key, (unsigned char*) old_nonce.c_str())) {
                            cout << "I may have lost this password..." << endl;
                            sodium_free(decrypted);
                            continue;
                        }

                        

                        // Encrypt again
                        // TODO: I don't know what
                        unsigned char new_nonce[crypto_secretbox_NONCEBYTES];
                        unsigned char new_cipher[crypto_secretbox_MACBYTES + strlen((char*) decrypted)];
                        encryptPassword(new_cipher, new_key, new_nonce, decrypted);
                        
                        if (decryptPassword(decrypted, new_cipher, new_key, new_nonce)) {
                            cout << "This should not happen... but it does :)" << endl;
                            sodium_free(decrypted);
                            continue;
                        }

                        sodium_free(decrypted);

                        // Store
                        new_siteFile.open(tmp_site_filename, ios::app);
                        new_siteFile << old_site << endl;
                        new_siteFile.close();

                        new_passwordFile.open(tmp_password_filename, ios::app);
                        new_passwordFile << base64_encode(new_cipher, sizeof (new_cipher)) << endl;
                        new_passwordFile.close();

                        new_nonceFile.open(tmp_nonce_filename, ios::app);                        
                        new_nonceFile << base64_encode(new_nonce, sizeof (new_nonce)) << endl;
                        new_nonceFile.close();

                    }
                    sodium_free(new_key);

                    old_siteFile.close();
                    old_passwordFile.close();
                    old_nonceFile.close();
                    

                    // Replace the old files by the new one.
                    remove(MASTER_PASSWORD_FILENAME);
                    remove(SITE_FILENAME);
                    remove(PASSWORD_FILENAME);
                    remove(NONCE_FILENAME);

                    rename(tmp_master_filename, MASTER_PASSWORD_FILENAME);
                    rename(tmp_site_filename, SITE_FILENAME);
                    rename(tmp_password_filename, PASSWORD_FILENAME);
                    rename(tmp_nonce_filename, NONCE_FILENAME);

                    cout << "To apply the changes, the app will now be locked." << endl;
                    state = LOCKED;
                    break;
                }
                case 4:
                {
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    sodium_free(key);
                    state = LOCKED;
                    break;
                }
                default:
                {
                    continue;
                }
            }
            if (cin.fail()) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        }
    }
    return EXIT_SUCCESS;
}

int hashMasterPassword(char * hash, const char * const password) {
    return crypto_pwhash_str(
            hash,
            password,
            strlen(password),
            crypto_pwhash_OPSLIMIT_MIN,
            crypto_pwhash_MEMLIMIT_MIN);
}

int checkMasterPassword(const char * const hash, const char * const password) {
    return crypto_pwhash_str_verify(
            hash,
            password,
            strlen(password));
}

int KDF(unsigned char * key, const char * const password, const unsigned char * const salt) {
    return crypto_pwhash(
            key,
            crypto_secretbox_KEYBYTES,
            password,
            strlen(password),
            salt,
            crypto_pwhash_OPSLIMIT_MIN,
            crypto_pwhash_MEMLIMIT_MIN,
            crypto_pwhash_ALG_DEFAULT);
}

void encryptPassword(unsigned char * cipher, unsigned char * key, unsigned char * nonce, unsigned char * message) {
    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(cipher, message, strlen((char*) message), nonce, key);
}

int decryptPassword(unsigned char * decrypted, unsigned char * cipher, unsigned char * key, unsigned char * nonce) {
    return crypto_secretbox_open_easy(decrypted, cipher, strlen((char*) cipher), nonce, key);
}

int identityCheck(char* masterPassword, FILE* masterFile) {
    if (!start) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        start = false;
    }

    char stored_hash[crypto_pwhash_STRBYTES];
    fgets(stored_hash, crypto_pwhash_STRBYTES, masterFile);
    fclose(masterFile);

    cout << "Enter your master password (max : " << MASTER_PASSWORD_LENGTH << ") and press return: ";
    fgets(masterPassword, MASTER_PASSWORD_LENGTH, stdin);

    // Clean the hash
    size_t len = strlen(stored_hash) - 1;
    if (len > 0 && stored_hash[len] == '\n') {
        stored_hash[len] = '\0';
    }
    return checkMasterPassword(stored_hash, masterPassword);
}

void newMaster(char* masterPassword, FILE * masterFile, char * hashed_password, unsigned char* salt, const char* const master_password_filename, const char* const site_filename, const char* const password_filename, const char* const nonce_filename) {
    // Create the files
    masterFile = fopen(master_password_filename, "wr+");

    FILE* tmp = fopen(site_filename, "wr+");
    fclose(tmp);
    tmp = fopen(password_filename, "wr+");
    fclose(tmp);
    tmp = fopen(nonce_filename, "wr+");
    fclose(tmp);


    cout << "Choose your master password (max : " << MASTER_PASSWORD_LENGTH << ") and press return: ";
    fgets(masterPassword, MASTER_PASSWORD_LENGTH, stdin);
    if (hashMasterPassword(hashed_password, masterPassword)) {
        sodium_free(masterPassword);
        fclose(masterFile);
        exit(EXIT_FAILURE);
    }

    // Create the salt for the kdf.
    randombytes_buf(salt, sizeof salt);

    // Put everything in the master file.
    fputs(hashed_password, masterFile);
    fputc('\n', masterFile);
    fputs(base64_encode(salt, sizeof (salt)).c_str(), masterFile);
    fputc('\n', masterFile);
    fclose(masterFile);
}

