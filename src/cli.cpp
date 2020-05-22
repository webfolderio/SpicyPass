/*  cli.cpp
 *
 *
 *  Copyright (C) 2020 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass.
 *
 *  SpicyPass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SpicyPass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SpicyPass.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "load.hpp"
#include "password.hpp"
#include "util.hpp"
#include "crypto.hpp"
#include "cli.hpp"

typedef enum {
    OPT_EXIT = 0,
    OPT_ADD,
    OPT_REMOVE,
    OPT_FETCH,
    OPT_LIST,
    OPT_GENERATE,
    OPT_PASSWORD,
    OPT_PRINT,
} Options;


/* Prompts password and puts it in `password` array.
 *
 * Return 0 on success.
 * Return -1 input is invalid.
 */
static int prompt_password(unsigned char *password, size_t max_length)
{
    std::cout << "Enter master password: ";

    char pass_buf[MAX_STORE_PASSWORD_SIZE + 2];
    const char *input = fgets(pass_buf, sizeof(pass_buf), stdin);

    if (input == NULL) {
        std::cout << "Invalid input." << std::endl;
        return -1;
    }

    size_t pass_length = strlen(pass_buf);

    if (pass_length > max_length) {
        return -1;
    }

    memcpy(password, pass_buf, pass_length);
    password[pass_length] = 0;

    crypto_memwipe((unsigned char *) pass_buf, sizeof(pass_buf));

    return 0;
}

static int new_password_prompt(Pass_Store &p, unsigned char *password, size_t max_length)
{
    while (true) {
        std::cout << "Enter new master password: ";

        // buffers are oversized by one byte for proper error reporting due to fgets weirdness
        char pass1[MAX_STORE_PASSWORD_SIZE + 3];
        char pass2[MAX_STORE_PASSWORD_SIZE + 3];

        const char *input1 = fgets(pass1, sizeof(pass1), stdin);
        std::cout << std::endl;

        if (p.check_lock()) {
            return PASS_STORE_LOCKED;
        }

        if (input1 == NULL) {
            std::cout << "Invalid input" << std::endl;
            continue;
        }

        size_t pass_length = strlen(pass1);

        if (pass_length < MIN_MASTER_PASSWORD_SIZE || pass_length > max_length) {
            std::cout << "Password must be between " << MIN_MASTER_PASSWORD_SIZE  << " and " << (max_length - 1) << " characters long" << std::endl;
            continue;
        }

        std::cout << "Enter password again: ";

        const char *input2 = fgets(pass2, sizeof(pass2), stdin);
        std::cout << std::endl;

        if (p.check_lock()) {
            return PASS_STORE_LOCKED;
        }

        if (input2 == NULL) {
            std::cout << "Invalid input" << std::endl;
            continue;
        }

        if (strcmp(pass1, pass2) != 0) {
            std::cout << "New passwords don't match" << std::endl;
            continue;
        }

        memcpy(password, pass1, pass_length);
        password[pass_length] = 0;

        crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
        crypto_memwipe((unsigned char *) pass2, sizeof(pass2));

        return 0;
    }
}

/*
 * Initializes pass store file with password hash on first run. Puts new password in
 * the `password` buffer.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Return PASS_STORE_LOCKED if pass store is locked.
 */
static int init_new_password(Pass_Store &p, unsigned char *password, size_t max_length)
{
    terminal_echo(false);
    int ret = new_password_prompt(p, password, max_length);
    terminal_echo(true);

    if (ret == PASS_STORE_LOCKED) {
        return ret;
    }

    std::cout << "Generating new encryption key. This can take a while" << std::endl;

    if (init_pass_hash(password, strlen((char *) password)) != 0) {
        std::cerr << "init_pass_hash() failed." << std::endl;
        return -1;
    }

    return 0;
}

/*
 * Prompts user to update password for pass store file.
 *
 * Return 0 on success.
 * Return -1 on failure.
 * Return PASS_STORE_LOCKED if pass store is locked.
 */
static int change_password_prompt(Pass_Store &p)
{
    unsigned char new_password[MAX_STORE_PASSWORD_SIZE + 2];
    unsigned char hash[CRYPTO_HASH_SIZE];
    p.get_password_hash(hash);

    std::cout << "Changing master password. Enter q to go back." << std::endl;

    while (true) {
        std::cout << "Enter old password: ";

        char old_pass[MAX_STORE_PASSWORD_SIZE + 2];
        const char *input1 = fgets(old_pass, sizeof(old_pass), stdin);
        std::cout << std::endl;

        if (p.check_lock()) {
            return PASS_STORE_LOCKED;
        }

        if (input1 == NULL) {
            std::cout << "Invalid input" << std::endl;
            continue;
        }

        if (strcmp(old_pass, "q\n") == 0) {
            return -1;
        }

        std::cout << "Validating password..." << std::endl;

        size_t pass_length = strlen(old_pass);

        if (!crypto_verify_pass_hash(hash, (unsigned char *) old_pass, pass_length)) {
            std::cout << "Invalid password" << std::endl;
            continue;
        }

        break;
    }

    if (new_password_prompt(p, new_password, sizeof(new_password) - 1) == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    std::cout << "Generating new encryption key..." << std::endl;

    int ret = update_crypto(p, new_password, strlen((char *) new_password));

    crypto_memwipe(new_password, sizeof(new_password));

    if (ret == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (ret < 0) {
        std::cerr << "Failed to update password (error code: " << std::to_string(ret) << ")" << std::endl;
        return -1;
    }

    std::cout << "Successfully updated password" << std::endl;

    return 0;
}

static int new_password(Pass_Store &p)
{
    terminal_echo(false);
    int ret = change_password_prompt(p);
    terminal_echo(true);

    return ret;
}

static int add(Pass_Store &p)
{
    std::string key, password;

    std::cout << "Enter key to add: ";
    getline(std::cin, key);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    if (key.length() > MAX_STORE_KEY_SIZE) {
        std::cout << "Key is too long" << std::endl;
        return -1;
    }

    if (key.length() == 0) {
        std::cout << "Invalid key" << std::endl;
        return -1;
    }

    if (!string_printable(key)) {
        std::cout << "Key may only contain printable ASCII characters" << std::endl;
        return -1;
    }

    std::cout << "Enter password (leave empty for a random password): ";
    getline(std::cin, password);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    if (password.length() > MAX_STORE_PASSWORD_SIZE) {
        std::cout << "Password length must not exceed " << std::to_string(MAX_STORE_PASSWORD_SIZE) << " characters" << std::endl;
        return -1;
    }

    if (password.empty()) {
        password = random_password(16U);

        if (password.empty()) {
            std::cout << "Failed to generate random password" << std::endl;
            return -1;
        }
    } else if (!string_printable(password)) {
        std::cout << "Password may only contain printable ASCII characters" << std::endl;
        return -1;
    }

    int exists = p.key_exists(key);

    if (exists == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (exists > 0) {
        while (true) {
            std::string s;
            std::cout << "Key \"" << key << "\" already exists. Overwrite? Y/n ";
            getline(std::cin, s);

            if (s == "Y" || s == "y") {
                break;
            } else if (s == "N" || s == "n") {
                return 0;
            }
        }
    }

    if (p.insert(key, password) != 0) {
        std::cout << "Failed to add entry" << std::endl;
        return -1;
    }

    int ret = save_password_store(p);

    switch (ret) {
        case 0: {
            std::cout << "Added key " << key << " with password " << password << std::endl;
            return 0;
        }
        case -1: {
            std::cerr << "Failed to save password store: Failed to open pass store file" << std::endl;
            return -1;
        }
        case -2: {
            std::cerr << "Failed to save password store: Encryption error" << std::endl;
            return -1;

        }
        case -3: {
            std::cerr << "Failed to save password store: File save error" << std::endl;
            return -1;
        }
        default: {
            std::cerr << "Failed to save password store: Unknown error" << std::endl;
            return -1;
        }
    }

    return 0;
}

static int remove(Pass_Store &p)
{
    std::string key;
    std::cout << "Enter key to remove: ";
    getline(std::cin, key);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    while (true) {
        std::cout << "Are you sure you want to remove the key \"" << key << "\" ? Y/n ";
        std::string s;
        getline(std::cin, s);

        if (p.check_lock()) {
            return PASS_STORE_LOCKED;
        }

        if (s == "y" || s == "Y") {
            break;
        } else if (s == "n" || s == "N") {
            return 0;
        }

        std::cout << "Invalid option" << std::endl;
    }

    int removed = p.remove(key);

    if (removed == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (removed != 0) {
        std::cout << "Key not found" << std::endl;
        return -1;
    }

    std::cout << "Removed \"" << key << "\" from pass store" << std::endl;

    int ret = save_password_store(p);

    if (ret != 0) {
        std::cerr << "Failed to save password store (error code: " << std::to_string(ret) << ")" << std::endl;
        return -1;
    }

    return 0;
}

static int fetch(Pass_Store &p)
{
    std::cout << "Enter key: ";

    std::string key;
    getline(std::cin, key);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    if (key.empty()) {
        return -1;
    }

    std::vector<std::tuple<std::string, const char *>> result;
    int matches = p.get_matches(key, result, false);

    if (matches == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (result.empty()) {
        std::cout << "Key not found" << std::endl;
        return -1;
    }

    p.s_lock();

    for (const auto &item: result) {
        std::cout << std::get<0>(item) << ": " << std::get<1>(item) << std::endl;
    }

    p.s_unlock();

    return 0;
}

static int list_entries(Pass_Store &p)
{
    std::vector<std::tuple<std::string, const char *>> result;
    int matches = p.get_matches("", result, false);

    if (matches == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    for (const auto &item: result) {
        std::cout << std::get<0>(item) << std::endl;
    }

    return 0;
}

static int generate(Pass_Store &p)
{
    std::string input;
    int size = 0;

    while (true) {
        std::cout << "Enter password length: ";
        getline(std::cin, input);

        if (p.check_lock()) {
            return PASS_STORE_LOCKED;
        }

        try {
            size = stoi(input);
        } catch (const std::exception &) {
            std::cout << "Invalid input" << std::endl;
            continue;
        }

        if (size >= NUM_RAND_PASS_MIN_CHARS && size <= NUM_RAND_PASS_MAX_CHARS) {
            break;
        }

        std::cout << "Password must be between " << std::to_string(NUM_RAND_PASS_MIN_CHARS) << " and " << std::to_string(NUM_RAND_PASS_MAX_CHARS) << " characters in length" << std::endl;
    }

    std::string pass = random_password(size);

    if (pass.empty()) {
        std::cout << "Failed to generate password" << std::endl;
        return -1;
    }

    std::cout << pass << std::endl;

    return 0;
}

static bool unlock_prompt(Pass_Store &p)
{
    std::cout << "Enter master password: ";

    unsigned char pass[MAX_STORE_PASSWORD_SIZE + 2];
    const char *input = fgets((char *) pass, sizeof(pass), stdin);
    std::cout << std::endl;

    if (input == NULL) {
        std::cout << "Invalid input" << std::endl;
        return false;
    }

    std::cout << "Decrypting pass store file..." << std::endl;

    int ret = load_password_store(p, pass, strlen((char *) pass));

    crypto_memwipe(pass, sizeof(pass));

    if (ret >= 0) {
        return true;
    }

    switch (ret) {
        case -1: {
            std::cerr << "Pass store file cannot be read" << std::endl;
            break;
        }
        case -2: {
            std::cout << "Invalid password" << std::endl;
            break;
        }
        case -3: {
            std::cerr << "Failed to decrypt pass store file" << std::endl;
            break;
        }
        case -4: {
            std::cerr << "Pass store file has bad format" << std::endl;
            break;
        }
        default: {
            std::cerr << "load_password_store() returned unknown error: " << std::to_string(ret) << std::endl;
            break;
        }
    }

    return false;
}

static void lock_check(Pass_Store &p)
{
    terminal_echo(false);

    while (!unlock_prompt(p))
        ;

    terminal_echo(true);
}

static void print_menu(void)
{
    std::cout << "Menu:" << std::endl;
    std::cout << "[" << std::to_string(OPT_ADD)        << "] Add entry" << std::endl;
    std::cout << "[" << std::to_string(OPT_REMOVE)     << "] Remove entry" << std::endl;
    std::cout << "[" << std::to_string(OPT_FETCH)      << "] Fetch entry" << std::endl;
    std::cout << "[" << std::to_string(OPT_LIST)       << "] List all entries" << std::endl;
    std::cout << "[" << std::to_string(OPT_GENERATE)   << "] Generate password" << std::endl;
    std::cout << "[" << std::to_string(OPT_PASSWORD)   << "] Change master password" << std::endl;
    std::cout << "[" << std::to_string(OPT_PRINT)      << "] Print menu" << std::endl;
    std::cout << "[" << std::to_string(OPT_EXIT)       << "] Exit" << std::endl;
}

/*
 * Executes command indicated by `option`.
 *
 * Return 0 on normal execution (including errors).
 * Return -1 on exit command.
 * Return PASS_STORE_LOCKED if pass store is locked.
 */
static int execute(const int option, Pass_Store &p)
{
    if (option == OPT_EXIT) {
        return -1;
    }

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    int ret = 0;

    switch (option) {
        case OPT_ADD: {
            ret = add(p);
            break;
        }
        case OPT_REMOVE: {
            ret = remove(p);
            break;
        }
        case OPT_FETCH: {
            ret = fetch(p);
            break;
        }
        case OPT_LIST: {
            ret = list_entries(p);
            break;
        }
        case OPT_GENERATE: {
            ret = generate(p);
            break;
        }
        case OPT_PASSWORD: {
            ret = new_password(p);
            break;
        }
        case OPT_PRINT: {
            print_menu();
            break;
        }
        default: {
            std::cout << "Invalid command. Enter " << std::to_string(OPT_PRINT) << " to print menu." << std::endl;
            break;
        }
    }

    return (ret != PASS_STORE_LOCKED) ? 0 : PASS_STORE_LOCKED;
}

static int command_prompt(void)
{
    std::cout << "> ";
    std::string prompt;
    getline(std::cin, prompt);

    try {
        return stoi(prompt);
    } catch (const std::exception &e) {
        return -1;
    }
}

/*
 * Initializes a new `Pass_Store` object and prompts user for password.
 *
 * Return 0 on success.
 * Return -1 if password prompt fails.
 * Return -2 if memory lock fails.
 * Return -3 if pass store file could not be opened.
 * Return -4 on invalid password.
 * Return -5 on decryption error.
 */
int cli_new_pass_store(Pass_Store &p)
{
    unsigned char password[MAX_STORE_PASSWORD_SIZE + 2];

    if (first_time_run()) {
        std::cout << "Creating a new profile. " << std::endl;

        if (init_new_password(p, password, sizeof(password) - 1) != 0) {
            return -1;
        }
    } else {
        terminal_echo(false);
        int pw_ret = prompt_password(password, sizeof(password) - 1);
        terminal_echo(true);

        std::cout << std::endl;

        if (pw_ret != 0) {
            return -1;
        }
    }

    std::cout << "Decrypting pass store file..." << std::endl;

    int ret = load_password_store(p, password, strlen((char *) password));

    crypto_memwipe(password, sizeof(password));

    if (ret >= 0) {
        std::cout << "Loaded " << std::to_string(ret) << " entries" << std::endl;
        return 0;
    }

    switch (ret) {
        case -1: {
            return -3;
        }
        case -2: {
            return -4;
        }
        case -3: {
            return -5;
        }
        case -4: {
            return -3;
        }
        default: {
            return -3;
        }
    }
}

static void menu_loop(Pass_Store &p)
{
    print_menu();

    while (true) {
        int option = command_prompt();
        int ret = execute(option, p);

        switch (ret) {
            case 0: {
                break;
            }
            case PASS_STORE_LOCKED: {
                lock_check(p);
                print_menu();
                break;
            }
            default: {
                return;
            }
        }
    }
}

void run_cli(Pass_Store &p)
{
    menu_loop(p);
    clear_console();
}