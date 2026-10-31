# Blanktick social kit

All files are in the blanktick.org "paper & kelp" design: cream `#FBFAF6`, ink `#17191B`, kelp `#0F4D3F`, the broken-tick logo, and the Hanken Grotesk, IBM Plex Mono and Newsreader fonts.

To change the design, edit `_build/gen.py` and run `bash _build/render.sh`. All PNGs are regenerated.

## Which file goes where

| Platform | Slot | File |
|---|---|---|
| **X / Twitter** | Header | `x-twitter-header-1500x500.png` |
| | Profile photo | `avatar-400x400.png` |
| **LinkedIn** | Company page cover | `linkedin-company-cover-1128x191.png` |
| | Personal profile background | `linkedin-personal-cover-1584x396.png` |
| | Company logo / profile photo | `avatar-400x400.png` |
| **Facebook** | Page cover | `facebook-cover-1640x624.png` |
| | Profile photo | `avatar-400x400.png` |
| **YouTube** | Channel banner | `youtube-channel-art-2560x1440.png` |
| | Profile photo | `avatar-1024x1024.png` |
| **Instagram** | Profile photo | `avatar-400x400.png` |
| | Feed post | `instagram-post-1080x1080.png` |
| | Feed post (taller) | `instagram-portrait-1080x1350.png` |
| | Story / Highlight cover | `instagram-tiktok-story-1080x1920.png` |
| **TikTok** | Profile photo | `avatar-400x400.png` |
| | Story / post image | `instagram-tiktok-story-1080x1920.png` |
| **Reddit** | Profile or community banner | `reddit-banner-1920x384.png` |
| | Avatar | `avatar-400x400.png` |
| **Discord** | Server banner | `discord-banner-960x540.png` |
| | Server icon | `avatar-400x400.png` |
| **GitHub** | Repo → Settings → Social preview | `og-github-social-preview-1280x640.png` |
| **Link previews** | Already set up on blanktick.org | `og-github-social-preview-1280x640.png` (served as `/og.png`) |

## Safe zones used

Copy and logo sit only inside these areas. The tick grid is decoration.

| Banner | What the safe zone avoids |
|---|---|
| X / Twitter | Left ~360 px, where the round profile photo overlaps |
| LinkedIn personal | Left ~460 px, where the profile photo overlaps |
| LinkedIn company | Left ~200 px, where the logo overlaps |
| Facebook | Left ~300 px (profile photo) and the outer sides (mobile crops them) |
| YouTube | Copy is inside the central 1546×423 that every device shows. TVs show the full image, phones show only the centre strip. |
| Story | Top 260 px and bottom 260 px, where the app UI sits |

Platform sizes change from time to time. If an upload screen asks for different dimensions, re-render with the new size in `gen.py` rather than stretching a PNG.

## Rule carried over from the brand

The "could not be checked" ticks are drawn in **ink**, which is darker than the green, and are never cropped off. The not-checked half must never be the quieter half. The numbers 50 / 31 match the website's receipt.
