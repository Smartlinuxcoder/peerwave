use dioxus::prelude::*;

#[component]
pub fn Home() -> Element {
    let mut wallpaper_url = use_signal(|| String::new());

    // Thx orangeci for the walls
    use_effect(move || {
        spawn(async move {
            let wallpapers = vec![
                "abandoned-trainstation.jpg",
                "abstract-swirls.jpg",
                "aesthetic.jpg",
                "artificial-valley.jpg",
                "asian-village.png",
                "astronaut.png",
                "atlantis.jpg",
                "bars.jpg",
                "basement.jpg",
                "beach-path.jpg",
                "beach.jpg",
                "berries-1.jpg",
                "berries-2.jpg",
                "biking-sunset.jpg",
                "black-hole.png",
                "blue-flowers.jpg",
                "blue-kaiju.png",
                "blue-landscape.png",
                "blueberries.jpg",
                "bluehour.jpg",
                "blueprint.png",
                "bsod.png",
                "bunnies-road.png",
                "c4-spring-sakura-sky.jpg",
                "cabin-2.jpg",
                "cabin-3.png",
                "cabin-4.png",
                "cabin.png",
                "call-it-a-day.jpg",
                "car-1.png",
                "car-wreck.png",
                "cartoon-castle.png",
                "castle.png",
                "cat-in-clouds.png",
                "cat-street.jpg",
                "cat-vibin.png",
                "chess-gate.jpeg",
                "city-harbor.png",
                "city-horizon.jpg",
                "city-on-water.jpg",
                "city.png",
                "clearing.png",
                "cliff-path.jpg",
                "cloud-coffee.jpg",
                "clouds-2.png",
                "clouds-3.jpg",
                "clouds-3.png",
                "clouds-5.jpg",
                "clouds.png",
                "coffee-shop.png",
                "cold-alley.png",
                "compass.jpg",
                "cool.jpg",
                "corals-fish-underwater.jpg",
                "cottages-river.png",
                "crane.png",
                "danbo.jpg",
                "dark-forest.jpg",
                "dark-star.jpg",
                "dark-waves.jpg",
                "day-forest-path.png",
                "deer-glade.jpg",
                "degirled.png",
                "desolate-city-2.jpg",
                "desolate-city.jpg",
                "diner-lonely-road.jpg",
                "dino.jpg",
                "disco.png",
                "dominik-mayer-1.jpg",
                "dominik-mayer-10.jpg",
                "dominik-mayer-11.jpg",
                "dominik-mayer-12.jpg",
                "dominik-mayer-13.jpg",
                "dominik-mayer-14.jpg",
                "dominik-mayer-15.jpg",
                "dominik-mayer-16.jpg",
                "dominik-mayer-17.jpg",
                "dominik-mayer-18.png",
                "dominik-mayer-19.jpg",
                "dominik-mayer-2.jpg",
                "dominik-mayer-20.jpg",
                "dominik-mayer-21.jpg",
                "dominik-mayer-22.jpg",
                "dominik-mayer-23.jpg",
                "dominik-mayer-24.jpg",
                "dominik-mayer-25.jpg",
                "dominik-mayer-26.jpg",
                "dominik-mayer-4.jpg",
                "dominik-mayer-5.jpg",
                "dominik-mayer-6.jpg",
                "dominik-mayer-7.jpg",
                "dominik-mayer-8.jpg",
                "dominik-mayer-9.jpg",
                "dragon.jpg",
                "droplets.png",
                "dwarf-saber.jpg",
                "eclipse.jpg",
                "excalibur-lake.jpg",
                "fantasy-city.jpg",
                "fight.jpg",
                "fishing.jpg",
                "flower-branch.png",
                "flower-field-2.png",
                "flower-field-3.png",
                "flower-field.jpg",
                "flower.jpg",
                "flowering-rain.png",
                "flowers-1.jpg",
                "flowers-10.jpg",
                "flowers-11.jpg",
                "flowers-12.jpg",
                "flowers-13.jpg",
                "flowers-14.jpg",
                "flowers-15.jpg",
                "flowers-16.jpg",
                "flowers-17.png",
                "flowers-18.jpg",
                "flowers-19.jpg",
                "flowers-2.jpg",
                "flowers-20.jpg",
                "flowers-21.png",
                "flowers-3.jpg",
                "flowers-4.jpg",
                "flowers-5.jpg",
                "flowers-6.jpg",
                "flowers-7.jpg",
                "flowers-8.jpg",
                "flowers-9.jpg",
                "flying-boat.jpg",
                "flying-comets-clouds.jpg",
                "foggy-city.jpg",
                "fox.png",
                "fumo-fumo.jpg",
                "galaxy-waves.jpg",
                "genshin-landscape.png",
                "gentlemen-sunset.png",
                "gingerbread-house.jpg",
                "girl-stars.png",
                "grandfather-tree.jpg",
                "grassy-well.jpg",
                "green-bridge.jpg",
                "greenbus.jpg",
                "harbor-3.png",
                "harbor.jpg",
                "haunted-house.jpg",
                "hollow-knight.jpg",
                "hollow-knight.png",
                "hollow.jpg",
                "horizon-2.jpg",
                "horizon.jpg",
                "i-touch-this.jpg",
                "ice-cream.jpg",
                "idk-tbh.png",
                "isekai.jpg",
                "japan-alley.png",
                "jellyfish.jpg",
                "jupiter.png",
                "kaiju.png",
                "keyboard-2.png",
                "keyboard.png",
                "kfc.jpg",
                "kitchen.png",
                "kitty.jpg",
                "kiwis.jpg",
                "knight-building.png",
                "knight-sit.png",
                "knight-templar.jpg",
                "knights-radiant.jpg",
                "koi.jpg",
                "koishi.jpg",
                "kusuriya.png",
                "lantern-light-room.png",
                "laundry.jpg",
                "lightbulbs.jpg",
                "lighthouse-2.png",
                "lighthouse.jpg",
                "link-click-1.png",
                "linux-communism.jpg",
                "lit-up-sky.png",
                "lovely-summer.jpg",
                "mage.jpg",
                "main-street.png",
                "maji-no-tabitabi-2.jpg",
                "maji-no-tabitabi-3.jpg",
                "majo-no-tabitabi.jpg",
                "map.png",
                "marine-tunnel.jpg",
                "math.png",
                "minimalist-black-hole.png",
                "misty-boat.jpg",
                "moon-beach.png",
                "moscow.jpg",
                "mountain-range.jpg",
                "mushishi.jpg",
                "my-neighbor-totoro-sunflowers.png",
                "old-car.jpg",
                "old-computer.png",
                "one-legged-herdazian.jpg",
                "orange.jpg",
                "oranges.jpg",
                "oversized-cat.jpg",
                "paint.jpg",
                "painting-standing.jpg",
                "painting.jpg",
                "panes.jpg",
                "pine.jpg",
                "pink-clouds.jpg",
                "pistachio-tea.jpg",
                "pitstop.png",
                "pixel-alley.png",
                "pixel-car.png",
                "pixel-castle.png",
                "pixel-earth.png",
                "pixel-galaxy.png",
                "pixel-napping.png",
                "pixel-planet.png",
                "pixel-prairie.jpg",
                "pixel-reading.png",
                "pizza.jpg",
                "plane-purple.png",
                "platform.jpg",
                "pompeii.png",
                "puffy-stars.jpg",
                "purple-horizon.jpg",
                "purpled-night.jpg",
                "railroad-2.jpg",
                "railroad-cat.png",
                "railroad-flowers.jpg",
                "railroad-horizon.png",
                "rainy-window.jpeg",
                "red-city.png",
                "retro2_live.gif",
                "river-city.jpg",
                "road.jpg",
                "rocket-launch.jpg",
                "rocket-schematics.jpg",
                "rooftops.jpg",
                "ruins.jpg",
                "sakura-aura.jpg",
                "sakura-gate.jpg",
                "sakura-trees-over-river.jpg",
                "salty-suburban.jpg",
                "samurai.jpg",
                "satellite.png",
                "scifi.jpg",
                "serenity.jpg",
                "shadow-shape-holo.jpeg",
                "ship-2.png",
                "ship-3.jpg",
                "shrimp-fried-rice.jpg",
                "signal-enthusiast.jpg",
                "snowflakes.jpg",
                "snowy-map.png",
                "snowy-train.jpg",
                "soaring-off.jpg",
                "soft-rose.jpg",
                "sousou-no-frieren-flowers.png",
                "south-pole.jpg",
                "space-piano.png",
                "space.jpg",
                "space.png",
                "square-city.jpg",
                "stall.jpg",
                "stormlight-archive.png",
                "street-4.png",
                "street.png",
                "subway.jpg",
                "sunken-tower.png",
                "sushi.jpg",
                "swirls.jpg",
                "swirly-painting.jpg",
                "sword.jpg",
                "tank.jpg",
                "temple.jpg",
                "toast.png",
                "tora.jpg",
                "touhou-house.jpg",
                "touhou-lake.jpg",
                "tower.png",
                "train-sideview.png",
                "train-station.jpg",
                "tree-stump.jpg",
                "tree.jpg",
                "trippy-purple.png",
                "trolley.jpg",
                "tux-socialism.jpg",
                "underwater-deep.jpg",
                "van-chilling.png",
                "venice-market.png",
                "vibrant-gate.png",
                "village-gate.jpg",
                "voxel-city.jpg",
                "voxel-houses-monochrome.png",
                "voyager-1.jpg",
                "voyager-10.jpg",
                "voyager-11.jpg",
                "voyager-12.jpg",
                "voyager-13.jpg",
                "voyager-14.jpg",
                "voyager-15.jpg",
                "voyager-16.jpg",
                "voyager-17.jpg",
                "voyager-18.jpg",
                "voyager-19.jpg",
                "voyager-2.jpg",
                "voyager-20.jpg",
                "voyager-21.jpg",
                "voyager-22.jpg",
                "voyager-3.jpg",
                "voyager-4.jpg",
                "voyager-5.jpg",
                "voyager-6.jpg",
                "voyager-7.jpg",
                "voyager-8.jpg",
                "voyager-9.jpg",
                "wall.jpg",
                "wallhaven-vqoo1p.jpg",
                "wanderer.jpg",
                "waterfall.png",
                "waves.png",
                "whale.jpg",
                "wheat.png",
                "windows-xp.jpg",
                "winter-flowers.jpg",
                "yohoho.jpg",
                "zuchold-archtecture.jpg",
            ];

            let random_index = (js_sys::Math::random() * wallpapers.len() as f64) as usize;
            wallpaper_url.set(format!(
                "https://raw.githubusercontent.com/orangci/walls-catppuccin-mocha/master/{}",
                wallpapers[random_index]
            ));
        });
    });

    rsx! {
        div {
            class: "min-h-screen relative overflow-hidden",

            if !wallpaper_url().is_empty() {
                div {
                    class: "absolute inset-0 bg-cover bg-center bg-no-repeat z-0",
                    style: "background-image: url('{wallpaper_url()}');"
                }
            }

            div {
                class: "absolute inset-0 bg-[var(--ctp-base)]/40 z-10"
            }

            div {
                class: "relative z-20 pt-8 pb-4 px-4 text-center",
                h1 {
                    class: "text-4xl md:text-6xl font-black mb-2 text-gradient-primary leading-tight",
                    "VaultMaxxing"
                }
                p {
                    class: "text-base text-[var(--ctp-subtext0)] mb-6 max-w-md mx-auto",
                    "We store stuff so noone else sees it"
                }
            }
            div {
                class: "relative z-20 px-4 pb-8",
                div {
                    class: "container mx-auto max-w-6xl",
                    div {
                        class: "flex flex-col lg:flex-row gap-6 items-start justify-center",

                        // Login
                        div {
                            class: "w-full lg:w-80 flex-shrink-0",
                            div {
                                class: "bg-gradient-to-br from-[var(--ctp-surface0)] via-[var(--ctp-surface1)] to-[var(--ctp-surface2)] rounded p-3 shadow-2xl border border-[var(--ctp-overlay0)] relative z-10",
                                h2 {
                                    class: "text-lg font-bold text-center mb-2 text-gradient-accent",
                                    "Log in"
                                }
                                div {
                                    class: "space-y-3",
                                    input {
                                        r#type: "text",
                                        placeholder: "Public key",
                                        class: "w-full px-4 py-3 bg-gradient-to-r from-[var(--ctp-mantle)] to-[var(--ctp-base)] border border-[var(--ctp-overlay0)] rounded text-[var(--ctp-text)] placeholder-[var(--ctp-subtext0)] focus:border-[var(--ctp-blue)] focus:outline-none focus:ring-2 focus:ring-[var(--ctp-blue)]/20 transition-all"
                                    }
                                    input {
                                        r#type: "password",
                                        placeholder: "Private key",
                                        class: "w-full px-4 py-3 bg-gradient-to-r from-[var(--ctp-mantle)] to-[var(--ctp-base)] border border-[var(--ctp-overlay0)] rounded text-[var(--ctp-text)] placeholder-[var(--ctp-subtext0)] focus:border-[var(--ctp-red)] focus:outline-none focus:ring-2 focus:ring-[var(--ctp-red)]/20 transition-all"
                                    }
                                    button {
                                        class: "w-full py-3 bg-gradient-to-r from-[var(--ctp-green)] via-[var(--ctp-teal)] to-[var(--ctp-sky)] text-[var(--ctp-base)] font-bold rounded-3xl shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 transition-all duration-300 hover:scale-[1.01] active:scale-[0.99]",
                                        "Access Vault"
                                    }
                                }
                            }
                        }
                        div {
                            class: "w-full lg:flex-1",
                            div {
                                class: "grid grid-cols-1 lg:grid-cols-3 gap-4",

                                // Security, red
                                div {
                                    class: "w-full bg-gradient-to-br from-[var(--ctp-red)]/20 to-[var(--ctp-maroon)]/20 backdrop-blur-sm border border-[var(--ctp-red)]/30 rounded-xl p-4 hover:scale-105 transition-transform duration-300 relative z-10",
                                    div {
                                        class: "w-10 h-10 bg-gradient-to-r from-[var(--ctp-red)] to-[var(--ctp-maroon)] rounded-lg flex items-center justify-center mb-3",
                                        svg {
                                            height: "14px",
                                            view_box: "0 0 448 512",
                                            xmlns: "http://www.w3.org/2000/svg",
                                            path { d: "M144 144l0 48 160 0 0-48c0-44.2-35.8-80-80-80s-80 35.8-80 80zM80 192l0-48C80 64.5 144.5 0 224 0s144 64.5 144 144l0 48 16 0c35.3 0 64 28.7 64 64l0 192c0 35.3-28.7 64-64 64L64 512c-35.3 0-64-28.7-64-64L0 256c0-35.3 28.7-64 64-64l16 0z" }
                                        }
                                    }
                                    h3 {
                                        class: "text-base font-bold text-[var(--ctp-text)] mb-1",
                                        "There aint no backdoor"
                                    }
                                    p {
                                        class: "text-sm text-[var(--ctp-subtext1)]",
                                        "RSA and quantum resistant encryption."
                                        br {  }
                                        "Also, you hold the keys"
                                    }
                                }

                                // Speed, blue
                                div {
                                    class: "w-full bg-gradient-to-br from-[var(--ctp-blue)]/20 to-[var(--ctp-sapphire)]/20 backdrop-blur-sm border border-[var(--ctp-blue)]/30 rounded-xl p-4 hover:scale-105 transition-transform duration-300 relative z-10",
                                    div {
                                        class: "w-10 h-10 bg-gradient-to-r from-[var(--ctp-blue)] to-[var(--ctp-sapphire)] rounded-lg flex items-center justify-center mb-3",
                                        svg {
                                            height: "14px",
                                            view_box: "0 0 448 512",
                                            xmlns: "http://www.w3.org/2000/svg",
                                            path { d: "M349.4 44.6c5.9-13.7 1.5-29.7-10.6-38.5s-28.6-8-39.9 1.8l-256 224c-10 8.8-13.6 22.9-8.9 35.3S50.7 288 64 288l111.5 0L98.6 467.4c-5.9 13.7-1.5 29.7 10.6 38.5s28.6 8 39.9-1.8l256-224c10-8.8 13.6-22.9 8.9-35.3s-16.6-20.7-30-20.7l-111.5 0L349.4 44.6z" }
                                        }
                                    }
                                    h3 {
                                        class: "text-base font-bold text-[var(--ctp-text)] mb-1",
                                        "BLAZINGLY Fast"
                                    }
                                    p {
                                        class: "text-sm text-[var(--ctp-subtext1)]",
                                        "Written in Rust, so it's fast as fuck"
                                        br {  }
                                        "- ThePrimeagen, probably"
                                    }
                                }

                                // Privacy, green
                                div {
                                    class: "w-full bg-gradient-to-br from-[var(--ctp-green)]/20 to-[var(--ctp-teal)]/20 backdrop-blur-sm border border-[var(--ctp-green)]/30 rounded-xl p-4 hover:scale-105 transition-transform duration-300 relative z-10",
                                    div {
                                        class: "w-10 h-10 bg-gradient-to-r from-[var(--ctp-green)] to-[var(--ctp-teal)] rounded-lg flex items-center justify-center mb-3",
                                        svg {
                                            height: "14px",
                                            view_box: "0 0 512 512",
                                            xmlns: "http://www.w3.org/2000/svg",
                                            path { d: "M256 0c4.6 0 9.2 1 13.4 2.9L457.7 82.8c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.6 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.7 2.9C246.8 1 251.4 0 256 0z" }
                                        }
                                    }
                                    h3 {
                                        class: "text-base font-bold text-[var(--ctp-text)] mb-1",
                                        "YouPrivacy"
                                    }
                                    p {
                                        class: "text-sm text-[var(--ctp-subtext1)]",
                                        "As long as you don't go around sharing your keys, you're good."
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
