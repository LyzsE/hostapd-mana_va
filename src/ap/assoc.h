#ifndef ASSOC_H
#define ASSOC_H


void handle_assoc(struct hostapd_data *hapd,
			 const struct ieee80211_mgmt *mgmt, size_t len,
			 int reassoc);
void sta_track_claim_taxonomy_info_assoc(struct hostapd_iface *iface, const u8 *addr,
				   struct wpabuf **assoc_ie_taxonomy);
#endif /* ASSOC_H */