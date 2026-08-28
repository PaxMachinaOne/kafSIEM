/*
 * kafSIEM
 * Portions derived from novatechflow/osint-siem and cyberdude88/osint-siem.
 * See NOTICE for provenance and LICENSE for repository-local terms.
 */

import L from "leaflet";
import { maplibreGL } from "@maplibre/maplibre-gl-leaflet";
import "maplibre-gl/dist/maplibre-gl.css";

export const OPENFREEMAP_TILE_ORIGIN = "https://tiles.openfreemap.org";
export const OPENFREEMAP_DARK_STYLE = `${OPENFREEMAP_TILE_ORIGIN}/styles/dark`;
export const OPENFREEMAP_ATTRIBUTION =
  '<a href="https://openfreemap.org">OpenFreeMap</a> <a href="https://www.openmaptiles.org/">&copy; OpenMapTiles</a> Data from <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>';

export function addDarkBasemap(map: L.Map): L.Layer {
  return maplibreGL({
    style: OPENFREEMAP_DARK_STYLE,
    attributionControl: false,
    interactive: false,
    renderWorldCopies: false,
  }).addTo(map);
}
