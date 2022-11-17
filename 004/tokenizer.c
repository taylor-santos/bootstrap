#include <stdio.h>
#include <string.h>

struct token {
    enum type {
        IDENT,
    } type;
    union {
        struct {
            const char *start;
            int len;
        } ident;
    };
};

int is_alpha(char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

void record_token(struct token token) {
    switch (token.type) {
        case IDENT:
            printf("IDENT: %.*s\n", token.ident.len, token.ident.start);
            break;
    }
}

void tokenize(const char *input, int len) {
    const char *end = input + len;
    for (; input < end; input++) {
        char c = *input;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        if (c == '#') {
            do {
                input++;
            } while (input < end && *input != '\n');
        }
        if (is_alpha(c)) {
            struct token ident;
            ident.type = IDENT;
            ident.ident.start = input;
            do {
                input++;
            } while (input < end && is_alpha(*input));
            ident.ident.len = input - ident.ident.start;
            record_token(ident);
        }
    }
}


int main(void) {
    const char *input = "foo bar #comment\nbaz.bop\n";
    int len = strlen(input);
    tokenize(input, len);
    return 0;
}