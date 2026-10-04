# Bash completion for gun101gkp.
# SPDX-License-Identifier: MIT

_gun101gkp()
{
    local cur prev command options

    COMPREPLY=()

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev=""

    if (( COMP_CWORD > 0 )); then
        prev="${COMP_WORDS[COMP_CWORD - 1]}"
    fi

    local commands="
        generate-identity
        show-identity
        fingerprint
        encrypt
        decrypt
        reset-identity
    "

    local global_options="-h --help --version"

    # Complete the first argument: global options or subcommands.
    if (( COMP_CWORD == 1 )); then
        COMPREPLY=(
            $(compgen -W "$commands $global_options" -- "$cur")
        )
        return 0
    fi

    command="${COMP_WORDS[1]}"

    # Arguments whose values are not predictable locally.
    case "$prev" in
        --recipient|--token)
            return 0
            ;;
        --output)
            compopt -o filenames 2>/dev/null || true
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
    esac

    # Complete command-specific options.
    if [[ "$cur" == -* ]]; then
        case "$command" in
            generate-identity)
                options="-h --help --passphrase"
                ;;
            show-identity)
                options="-h --help"
                ;;
            fingerprint)
                options="-h --help --token"
                ;;
            encrypt)
                options="-h --help --recipient --output"
                ;;
            decrypt)
                options="-h --help --passphrase --output"
                ;;
            reset-identity)
                options="-h --help"
                ;;
            *)
                options="$global_options"
                ;;
        esac

        COMPREPLY=( $(compgen -W "$options" -- "$cur") )
        return 0
    fi

    # encrypt/decrypt take a file as their positional argument.
    case "$command" in
        encrypt|decrypt)
            compopt -o filenames 2>/dev/null || true
            COMPREPLY=( $(compgen -f -- "$cur") )
            ;;
    esac

    return 0
}

complete -F _gun101gkp gun101gkp
