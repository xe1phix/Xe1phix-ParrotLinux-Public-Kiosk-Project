#! /bin/bash
#
# Diffusion youtube avec ffmpeg

# Configurer youtube avec une résolution 720p. La vidéo n'est pas scalée.

VBR="2500k"                                    # Bitrate de la vidéo en sortie
FPS="30"                                       # FPS de la vidéo en sortie
QUAL="medium"                                  # Preset de qualité FFMPEG
YOUTUBE_URL="*"  # URL de base RTMP youtube
OVERLAY="*" # Chemin de l'overlay

SOURCE="*"              # Source UDP (voir les annonces SAP)
KEY="*"                                     # Clé à récupérer sur l'event youtube

ffmpeg \
    -i "$SOURCE" -i "$OVERLAY" \
    -filter_complex "[0:v][1:v] overlay=25:25:enable='between(t,0,20)'" \
    -vcodec libx264 -pix_fmt yuv420p -preset $QUAL -r $FPS -g $(($FPS * 2)) -b:v $VBR \
    -acodec libmp3lame -ar 44100 -threads 6 -qscale 3 -b:a 712000 -bufsize 512k \
    -f flv "$YOUTUBE_URL/$KEY"