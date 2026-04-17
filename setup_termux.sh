#!/data/data/com.termux/files/usr/bin/bash

echo "Iniciando configuracion de Termux..."
echo ""

# Actualizar sistema
echo "[1/10] Actualizando paquetes..."
pkg update -y && pkg upgrade -y

# Instalar paquetes basicos
echo "[2/10] Instalando paquetes basicos..."
pkg install -y zsh git curl wget unzip nano vim

# Instalar Oh My Posh
echo "[3/10] Instalando Oh My Posh..."
curl -s https://ohmyposh.dev/install.sh | bash -s -- -d ~/.local/bin
export PATH=$PATH:~/.local/bin

# Configurar Nerd Font
echo "[4/10] Configurando Nerd Font..."
mkdir -p ~/.termux
cd ~/.termux
curl -fLo "font.ttf" https://github.com/ryanoasis/nerd-fonts/raw/master/patched-fonts/JetBrainsMono/Ligatures/Regular/JetBrainsMonoNerdFont-Regular.ttf

# Instalar plugins de zsh
echo "[5/10] Instalando plugins de zsh..."
mkdir -p ~/.zsh
git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions 2>/dev/null || echo "Ya existe"
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh/zsh-syntax-highlighting 2>/dev/null || echo "Ya existe"
git clone https://github.com/zsh-users/zsh-completions.git ~/.zsh/zsh-completions 2>/dev/null || echo "Ya existe"

# Crear configuracion de zsh
echo "[6/10] Creando configuracion de .zshrc..."

# Remove old .zshrc if exists (to avoid CRLF issues)
[ -f ~/.zshrc ] && rm ~/.zshrc

cat > ~/.zshrc << 'EOF'
# PATH
export PATH=$PATH:~/.local/bin

# Oh My Posh (disabled to avoid fetch errors in Termux)
# if command -v oh-my-posh &> /dev/null; then
#     eval "$(oh-my-posh init zsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/atomic.omp.json)"
# fi

# Custom prompt (simple and reliable)
PROMPT='%F{cyan}%n@termux%f %F{yellow}%~%f %# '

# HISTORY
HISTFILE=~/.zsh_history
HISTSIZE=10000
SAVEHIST=10000
setopt SHARE_HISTORY
setopt HIST_IGNORE_ALL_DUPS
setopt HIST_IGNORE_SPACE
setopt APPEND_HISTORY
setopt INC_APPEND_HISTORY

# AUTOCOMPLETADO
autoload -U compinit && compinit
zstyle ':completion:*' menu select
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
fpath=(~/.zsh/zsh-completions/src $fpath)

# KEYBINDINGS
bindkey '^[[A' history-search-backward
bindkey '^[[B' history-search-forward
bindkey '^[[1;5C' forward-word
bindkey '^[[1;5D' backward-word
bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line
bindkey '^[[3~' delete-char

# ALIASES GENERALES
alias ll='ls -lah --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ls='ls --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias h='cd ~'
alias d='cd ~/storage/downloads'
alias doc='cd ~/storage/documents'

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit -m'
alias gp='git push'
alias gl='git log --oneline --graph --decorate'

# ALIASES SECURITY
alias nmapscan='nmap -sV -sC -O -A'
alias nmafall='nmap -p-'
alias ports='netstat -tulanp'
alias myip='curl ifconfig.me'
alias iplookup='curl ipinfo.io/'
alias py='python'
alias py3='python3'
alias cls='clear'
alias c='clear'

# FUNCIONES
quickscan() {
    if [ -z "$1" ]; then
        echo "Uso: quickscan <IP>"
        return 1
    fi
    nmap -sV -sC "$1"
}

mkcd() {
    mkdir -p "$1" && cd "$1"
}

extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.gz)   tar xzf "$1"    ;;
            *.tar.bz2)  tar xjf "$1"    ;;
            *.tar)      tar xf "$1"     ;;
            *.zip)      unzip "$1"      ;;
            *.gz)       gunzip "$1"     ;;
            *.bz2)      bunzip2 "$1"    ;;
            *.rar)      unrar x "$1"    ;;
            *.7z)       7z x "$1"       ;;
            *)          echo "No se como extraer '$1'" ;;
        esac
    else
        echo "'$1' no es un archivo valido"
    fi
}

# PLUGINS
[ -f ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh ] && source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh
[ -f ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=240'

echo ""
echo "==================================="
echo "  Termux Purple Team Edition"
echo "==================================="
echo ""
EOF

# Instalar herramientas de seguridad
echo "[7/10] Instalando herramientas de seguridad..."
pkg install -y python python-pip nmap hydra openssh nodejs ruby perl golang netcat-openbsd dnsutils whois curl wget jq tree

# Configurar storage de Android
echo "[8/10] Configurando acceso al storage..."
termux-setup-storage

# Cambiar shell por defecto a zsh
echo "[9/10] Configurando zsh como shell por defecto..."
chsh -s zsh

# Configuracion de colores
echo "[10/10] Aplicando tema de colores..."
cat > ~/.termux/colors.properties << 'EOF'
background=#282a36
foreground=#f8f8f2
cursor=#f8f8f2
color0=#21222c
color1=#ff5555
color2=#50fa7b
color3=#f1fa8c
color4=#bd93f9
color5=#ff79c6
color6=#8be9fd
color7=#f8f8f2
color8=#6272a4
color9=#ff6e6e
color10=#69ff94
color11=#ffffa5
color12=#d6acff
color13=#ff92df
color14=#a4ffff
color15=#ffffff
EOF

echo ""
echo "=========================================="
echo "Instalacion completada!"
echo ""
echo "Para aplicar los cambios ejecuta:"
echo "  termux-reload-settings"
echo "  zsh"
echo ""
echo "=========================================="
