#include "utils/includes.h"

#ifndef CONFIG_NATIVE_WINDOWS

#include "utils/common.h"
#include "utils/eloop.h"
#include "crypto/crypto.h"
#include "crypto/sha256.h"
#include "crypto/random.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/wpa_ctrl.h"
#include "common/sae.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "p2p/p2p.h"
#include "wps/wps.h"
#include "fst/fst.h"
#include "hostapd.h"
#include "beacon.h"
#include "ieee802_11_auth.h"
#include "sta_info.h"
#include "ieee802_1x.h"
#include "wpa_auth.h"
#include "pmksa_cache_auth.h"
#include "wmm.h"
#include "ap_list.h"
#include "accounting.h"
#include "ap_config.h"
#include "ap_mlme.h"
#include "p2p_hostapd.h"
#include "ap_drv_ops.h"
#include "wnm_ap.h"
#include "hw_features.h"
#include "ieee802_11.h"
#include "dfs.h"
#include "mbo_ap.h"
#include "rrm.h"
#include "taxonomy.h"
#include "hs20.h"
#include "common/hw_features_common.h"
// MANA START
#include "common/mana.h" //MANA

//struct mana_mac *mana_machash = NULL;
//struct mana_ssid *mana_ssidhash = NULL;
// MANA END

extern int handle_type_assoc_probe;



static u16 check_ssid(struct hostapd_data *hapd, struct sta_info *sta,
		      const u8 *ssid_ie, size_t ssid_ie_len)
{
	if (ssid_ie == NULL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	if (hapd->iconf->enable_mana) {
		wpa_printf(MSG_MSGDUMP, "MANA - Checking SSID for start of association, pass through %s", wpa_ssid_txt(ssid_ie, ssid_ie_len));
		return WLAN_STATUS_SUCCESS;
	} else {
		if (ssid_ie_len != hapd->conf->ssid.ssid_len ||
			os_memcmp(ssid_ie, hapd->conf->ssid.ssid, ssid_ie_len) != 0) {
			hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
					   HOSTAPD_LEVEL_INFO,
					   "Station tried to associate with unknown SSID "
					   "'%s'", wpa_ssid_txt(ssid_ie, ssid_ie_len));
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}

	return WLAN_STATUS_SUCCESS;
	}
}


static u16 check_wmm(struct hostapd_data *hapd, struct sta_info *sta,
		     const u8 *wmm_ie, size_t wmm_ie_len)
{
	sta->flags &= ~WLAN_STA_WMM;
	sta->qosinfo = 0;
	if (wmm_ie && hapd->conf->wmm_enabled) {
		struct wmm_information_element *wmm;

		if (!hostapd_eid_wmm_valid(hapd, wmm_ie, wmm_ie_len)) {
			hostapd_logger(hapd, sta->addr,
				       HOSTAPD_MODULE_WPA,
				       HOSTAPD_LEVEL_DEBUG,
				       "invalid WMM element in association "
				       "request");
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}

		sta->flags |= WLAN_STA_WMM;
		wmm = (struct wmm_information_element *) wmm_ie;
		sta->qosinfo = wmm->qos_info;
	}
	return WLAN_STATUS_SUCCESS;
}


static u16 copy_supp_rates(struct hostapd_data *hapd, struct sta_info *sta,
			   struct ieee802_11_elems *elems)
{
	if (!elems->supp_rates) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "No supported rates element in AssocReq");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (elems->supp_rates_len + elems->ext_supp_rates_len >
	    sizeof(sta->supported_rates)) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "Invalid supported rates element length %d+%d",
			       elems->supp_rates_len,
			       elems->ext_supp_rates_len);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->supported_rates_len = merge_byte_arrays(
		sta->supported_rates, sizeof(sta->supported_rates),
		elems->supp_rates, elems->supp_rates_len,
		elems->ext_supp_rates, elems->ext_supp_rates_len);

	return WLAN_STATUS_SUCCESS;
}


static u16 check_ext_capab(struct hostapd_data *hapd, struct sta_info *sta,
			   const u8 *ext_capab_ie, size_t ext_capab_ie_len)
{
#ifdef CONFIG_INTERWORKING
	/* check for QoS Map support */
	if (ext_capab_ie_len >= 5) {
		if (ext_capab_ie[4] & 0x01)
			sta->qos_map_enabled = 1;
	}
#endif /* CONFIG_INTERWORKING */

	if (ext_capab_ie_len > 0)
		sta->ecsa_supported = !!(ext_capab_ie[0] & BIT(2));

	return WLAN_STATUS_SUCCESS;
}




static void log_ssid(struct hostapd_data *hapd, const u8 *ssid, size_t ssid_len, const u8 *mac) {
	if (os_strcmp("NOT_SET", hapd->iconf->mana_outfile) == 0) {
		return; // File not set, so don't log
	}
	//FILE *f = fopen(hapd->iconf->mana_outfile, "a");
	FILE *fa = fopen(hapd->iconf->mana_outfile_assoc, "a");
	if (fa != NULL) {
		int rand=0;
		if (mac[0] & 2) //Check if locally administered aka random MAC
			rand=1; 

#ifdef CONFIG_TAXONOMY
		struct sta_info *sta; //sta contains information about station, not frame
		struct hostapd_sta_info *info;
		char reply[512] = "";
		size_t reply_len = 512;
		printf("\nHandle type triggered: %d\n\n", handle_type_assoc_probe);
		if (((sta = ap_get_sta(hapd, mac)) != NULL)&&(handle_type_assoc_probe == 1)) {
			retrieve_sta_taxonomy(hapd, sta, reply, reply_len);
			//fprintf(f,MACSTR ", %s, %d, %s\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand, reply);

			fprintf(fa,MACSTR ", %s, %d, %s\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand, reply);
			//
		} else if (((info = sta_track_get(hapd->iface, mac)) != NULL)&&(handle_type_assoc_probe == 1)) {
			//char reply[512] = "";
			//size_t reply_len = 512;
			retrieve_hostapd_sta_taxonomy(hapd, info, reply, reply_len);
			fprintf(fa,MACSTR ", %s, %d, %s\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand, reply);

			//
		} else {
			//fprintf(f,MACSTR ", %s, %d\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand);
			//
			fprintf(fa,MACSTR ", %s, %d\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand);
			//
		}
#endif /* CONFIG_TAXONOMY */
#ifndef CONFIG_TAXONOMY
		fprintf(fa,MACSTR ", %s, %d\n", MAC2STR(mac), wpa_ssid_txt(ssid, ssid_len), rand);
#endif /* CONFIG_TAXONOMY */
		fclose(fa);
	} else
		wpa_printf(MSG_ERROR, "MANA: Error writing to activity file %s", hapd->iconf->mana_outfile);
}
//End MANA

//Зависимость handle_assoc()
static u16 check_assoc_ies(struct hostapd_data *hapd, struct sta_info *sta,
			   const u8 *ies, size_t ies_len, int reassoc)
{
	struct ieee802_11_elems elems;
	u16 resp;
	const u8 *wpa_ie;
	size_t wpa_ie_len;
	const u8 *p2p_dev_addr = NULL;

	if (ieee802_11_parse_elems(ies, ies_len, &elems, 1) == ParseFailed) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "Station sent an invalid "
			       "association request");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	resp = check_ssid(hapd, sta, elems.ssid, elems.ssid_len);
	if (resp != WLAN_STATUS_SUCCESS)
		return resp;
	resp = check_wmm(hapd, sta, elems.wmm, elems.wmm_len);
	if (resp != WLAN_STATUS_SUCCESS)
		return resp;
	resp = check_ext_capab(hapd, sta, elems.ext_capab, elems.ext_capab_len);
	if (resp != WLAN_STATUS_SUCCESS)
		return resp;
	resp = copy_supp_rates(hapd, sta, &elems);
	if (resp != WLAN_STATUS_SUCCESS)
		return resp;
#ifdef CONFIG_IEEE80211N
	resp = copy_sta_ht_capab(hapd, sta, elems.ht_capabilities);
	if (resp != WLAN_STATUS_SUCCESS)
		return resp;
	if (hapd->iconf->ieee80211n && hapd->iconf->require_ht &&
	    !(sta->flags & WLAN_STA_HT)) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "Station does not support "
			       "mandatory HT PHY - reject association");
		return WLAN_STATUS_ASSOC_DENIED_NO_HT;
	}
#endif /* CONFIG_IEEE80211N */

#ifdef CONFIG_IEEE80211AC
	if (hapd->iconf->ieee80211ac) {
		resp = copy_sta_vht_capab(hapd, sta, elems.vht_capabilities);
		if (resp != WLAN_STATUS_SUCCESS)
			return resp;

		resp = set_sta_vht_opmode(hapd, sta, elems.vht_opmode_notif);
		if (resp != WLAN_STATUS_SUCCESS)
			return resp;
	}

	if (hapd->iconf->ieee80211ac && hapd->iconf->require_vht &&
	    !(sta->flags & WLAN_STA_VHT)) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "Station does not support "
			       "mandatory VHT PHY - reject association");
		return WLAN_STATUS_ASSOC_DENIED_NO_VHT;
	}

	if (hapd->conf->vendor_vht && !elems.vht_capabilities) {
		resp = copy_sta_vendor_vht(hapd, sta, elems.vendor_vht,
					   elems.vendor_vht_len);
		if (resp != WLAN_STATUS_SUCCESS)
			return resp;
	}
#endif /* CONFIG_IEEE80211AC */

#ifdef CONFIG_P2P
	if (elems.p2p) {
		wpabuf_free(sta->p2p_ie);
		sta->p2p_ie = ieee802_11_vendor_ie_concat(ies, ies_len,
							  P2P_IE_VENDOR_TYPE);
		if (sta->p2p_ie)
			p2p_dev_addr = p2p_get_go_dev_addr(sta->p2p_ie);
	} else {
		wpabuf_free(sta->p2p_ie);
		sta->p2p_ie = NULL;
	}
#endif /* CONFIG_P2P */

	if ((hapd->conf->wpa & WPA_PROTO_RSN) && elems.rsn_ie) {
		wpa_ie = elems.rsn_ie;
		wpa_ie_len = elems.rsn_ie_len;
	} else if ((hapd->conf->wpa & WPA_PROTO_WPA) &&
		   elems.wpa_ie) {
		wpa_ie = elems.wpa_ie;
		wpa_ie_len = elems.wpa_ie_len;
	} else {
		wpa_ie = NULL;
		wpa_ie_len = 0;
	}

#ifdef CONFIG_WPS
	sta->flags &= ~(WLAN_STA_WPS | WLAN_STA_MAYBE_WPS | WLAN_STA_WPS2);
	if (hapd->conf->wps_state && elems.wps_ie) {
		wpa_printf(MSG_DEBUG, "STA included WPS IE in (Re)Association "
			   "Request - assume WPS is used");
		sta->flags |= WLAN_STA_WPS;
		wpabuf_free(sta->wps_ie);
		sta->wps_ie = ieee802_11_vendor_ie_concat(ies, ies_len,
							  WPS_IE_VENDOR_TYPE);
		if (sta->wps_ie && wps_is_20(sta->wps_ie)) {
			wpa_printf(MSG_DEBUG, "WPS: STA supports WPS 2.0");
			sta->flags |= WLAN_STA_WPS2;
		}
		wpa_ie = NULL;
		wpa_ie_len = 0;
		if (sta->wps_ie && wps_validate_assoc_req(sta->wps_ie) < 0) {
			wpa_printf(MSG_DEBUG, "WPS: Invalid WPS IE in "
				   "(Re)Association Request - reject");
			return WLAN_STATUS_INVALID_IE;
		}
	} else if (hapd->conf->wps_state && wpa_ie == NULL) {
		wpa_printf(MSG_DEBUG, "STA did not include WPA/RSN IE in "
			   "(Re)Association Request - possible WPS use");
		sta->flags |= WLAN_STA_MAYBE_WPS;
	} else
#endif /* CONFIG_WPS */
	if (hapd->conf->wpa && wpa_ie == NULL) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO,
			       "No WPA/RSN IE in association request");
		return WLAN_STATUS_INVALID_IE;
	}

	if (hapd->conf->wpa && wpa_ie) {
		int res;
		wpa_ie -= 2;
		wpa_ie_len += 2;
		if (sta->wpa_sm == NULL)
			sta->wpa_sm = wpa_auth_sta_init(hapd->wpa_auth,
							sta->addr,
							p2p_dev_addr);
		if (sta->wpa_sm == NULL) {
			wpa_printf(MSG_WARNING, "Failed to initialize WPA "
				   "state machine");
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
		res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,
					  wpa_ie, wpa_ie_len,
					  elems.mdie, elems.mdie_len);
		if (res == WPA_INVALID_GROUP)
			resp = WLAN_STATUS_GROUP_CIPHER_NOT_VALID;
		else if (res == WPA_INVALID_PAIRWISE)
			resp = WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID;
		else if (res == WPA_INVALID_AKMP)
			resp = WLAN_STATUS_AKMP_NOT_VALID;
		else if (res == WPA_ALLOC_FAIL)
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
#ifdef CONFIG_IEEE80211W
		else if (res == WPA_MGMT_FRAME_PROTECTION_VIOLATION)
			resp = WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION;
		else if (res == WPA_INVALID_MGMT_GROUP_CIPHER)
			resp = WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION;
#endif /* CONFIG_IEEE80211W */
		else if (res == WPA_INVALID_MDIE)
			resp = WLAN_STATUS_INVALID_MDIE;
		else if (res != WPA_IE_OK)
			resp = WLAN_STATUS_INVALID_IE;
		if (resp != WLAN_STATUS_SUCCESS)
			return resp;
#ifdef CONFIG_IEEE80211W
		if ((sta->flags & WLAN_STA_MFP) && !sta->sa_query_timed_out &&
		    sta->sa_query_count > 0)
			ap_check_sa_query_timeout(hapd, sta);
		if ((sta->flags & WLAN_STA_MFP) && !sta->sa_query_timed_out &&
		    (!reassoc || sta->auth_alg != WLAN_AUTH_FT)) {
			/*
			 * STA has already been associated with MFP and SA
			 * Query timeout has not been reached. Reject the
			 * association attempt temporarily and start SA Query,
			 * if one is not pending.
			 */

			if (sta->sa_query_count == 0)
				ap_sta_start_sa_query(hapd, sta);

			return WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY;
		}

		if (wpa_auth_uses_mfp(sta->wpa_sm))
			sta->flags |= WLAN_STA_MFP;
		else
			sta->flags &= ~WLAN_STA_MFP;
#endif /* CONFIG_IEEE80211W */

#ifdef CONFIG_IEEE80211R
		if (sta->auth_alg == WLAN_AUTH_FT) {
			if (!reassoc) {
				wpa_printf(MSG_DEBUG, "FT: " MACSTR " tried "
					   "to use association (not "
					   "re-association) with FT auth_alg",
					   MAC2STR(sta->addr));
				return WLAN_STATUS_UNSPECIFIED_FAILURE;
			}

			resp = wpa_ft_validate_reassoc(sta->wpa_sm, ies,
						       ies_len);
			if (resp != WLAN_STATUS_SUCCESS)
				return resp;
		}
#endif /* CONFIG_IEEE80211R */

#ifdef CONFIG_SAE
		if (wpa_auth_uses_sae(sta->wpa_sm) &&
		    sta->auth_alg == WLAN_AUTH_OPEN) {
			struct rsn_pmksa_cache_entry *sa;
			sa = wpa_auth_sta_get_pmksa(sta->wpa_sm);
			if (!sa || sa->akmp != WPA_KEY_MGMT_SAE) {
				wpa_printf(MSG_DEBUG,
					   "SAE: No PMKSA cache entry found for "
					   MACSTR, MAC2STR(sta->addr));
				return WLAN_STATUS_INVALID_PMKID;
			}
			wpa_printf(MSG_DEBUG, "SAE: " MACSTR
				   " using PMKSA caching", MAC2STR(sta->addr));
		} else if (wpa_auth_uses_sae(sta->wpa_sm) &&
			   sta->auth_alg != WLAN_AUTH_SAE &&
			   !(sta->auth_alg == WLAN_AUTH_FT &&
			     wpa_auth_uses_ft_sae(sta->wpa_sm))) {
			wpa_printf(MSG_DEBUG, "SAE: " MACSTR " tried to use "
				   "SAE AKM after non-SAE auth_alg %u",
				   MAC2STR(sta->addr), sta->auth_alg);
			return WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG;
		}
#endif /* CONFIG_SAE */

#ifdef CONFIG_IEEE80211N
		if ((sta->flags & (WLAN_STA_HT | WLAN_STA_VHT)) &&
		    wpa_auth_get_pairwise(sta->wpa_sm) == WPA_CIPHER_TKIP) {
			hostapd_logger(hapd, sta->addr,
				       HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_INFO,
				       "Station tried to use TKIP with HT "
				       "association");
			return WLAN_STATUS_CIPHER_REJECTED_PER_POLICY;
		}
#endif /* CONFIG_IEEE80211N */
#ifdef CONFIG_HS20
	} else if (hapd->conf->osen) {
		if (elems.osen == NULL) {
			hostapd_logger(
				hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
				HOSTAPD_LEVEL_INFO,
				"No HS 2.0 OSEN element in association request");
			return WLAN_STATUS_INVALID_IE;
		}

		wpa_printf(MSG_DEBUG, "HS 2.0: OSEN association");
		if (sta->wpa_sm == NULL)
			sta->wpa_sm = wpa_auth_sta_init(hapd->wpa_auth,
							sta->addr, NULL);
		if (sta->wpa_sm == NULL) {
			wpa_printf(MSG_WARNING, "Failed to initialize WPA "
				   "state machine");
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
		if (wpa_validate_osen(hapd->wpa_auth, sta->wpa_sm,
				      elems.osen - 2, elems.osen_len + 2) < 0)
			return WLAN_STATUS_INVALID_IE;
#endif /* CONFIG_HS20 */
	} else
		wpa_auth_sta_no_wpa(sta->wpa_sm);

#ifdef CONFIG_P2P
	p2p_group_notif_assoc(hapd->p2p_group, sta->addr, ies, ies_len);
#endif /* CONFIG_P2P */

#ifdef CONFIG_HS20
	wpabuf_free(sta->hs20_ie);
	if (elems.hs20 && elems.hs20_len > 4) {
		sta->hs20_ie = wpabuf_alloc_copy(elems.hs20 + 4,
						 elems.hs20_len - 4);
	} else
		sta->hs20_ie = NULL;
#endif /* CONFIG_HS20 */

#ifdef CONFIG_FST
	wpabuf_free(sta->mb_ies);
	if (hapd->iface->fst)
		sta->mb_ies = mb_ies_by_info(&elems.mb_ies);
	else
		sta->mb_ies = NULL;
#endif /* CONFIG_FST */

#ifdef CONFIG_MBO
	mbo_ap_check_sta_assoc(hapd, sta, &elems);

	if (hapd->conf->mbo_enabled && (hapd->conf->wpa & 2) &&
	    elems.mbo && sta->cell_capa && !(sta->flags & WLAN_STA_MFP) &&
	    hapd->conf->ieee80211w != NO_MGMT_FRAME_PROTECTION) {
		wpa_printf(MSG_INFO,
			   "MBO: Reject WPA2 association without PMF");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
#endif /* CONFIG_MBO */

	ap_copy_sta_supp_op_classes(sta, elems.supp_op_classes,
				    elems.supp_op_classes_len);

	if ((sta->capability & WLAN_CAPABILITY_RADIO_MEASUREMENT) &&
	    elems.rrm_enabled &&
	    elems.rrm_enabled_len >= sizeof(sta->rrm_enabled_capa))
		os_memcpy(sta->rrm_enabled_capa, elems.rrm_enabled,
			  sizeof(sta->rrm_enabled_capa));

	return WLAN_STATUS_SUCCESS;
}

//Зависимость handle_assoc()
static void send_deauth(struct hostapd_data *hapd, const u8 *addr,
			u16 reason_code)
{
	int send_len;
	struct ieee80211_mgmt reply;

	os_memset(&reply, 0, sizeof(reply));
	reply.frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_DEAUTH);
	os_memcpy(reply.da, addr, ETH_ALEN);
	os_memcpy(reply.sa, hapd->own_addr, ETH_ALEN);
	os_memcpy(reply.bssid, hapd->own_addr, ETH_ALEN);

	send_len = IEEE80211_HDRLEN + sizeof(reply.u.deauth);
	reply.u.deauth.reason_code = host_to_le16(reason_code);

	if (hostapd_drv_send_mlme(hapd, &reply, send_len, 0) < 0)
		wpa_printf(MSG_INFO, "Failed to send deauth: %s",
			   strerror(errno));
}


//Зависимость handle_assoc()
static int add_associated_sta(struct hostapd_data *hapd,
			      struct sta_info *sta)
{
	struct ieee80211_ht_capabilities ht_cap;
	struct ieee80211_vht_capabilities vht_cap;

	/*
	 * Remove the STA entry to ensure the STA PS state gets cleared and
	 * configuration gets updated. This is relevant for cases, such as
	 * FT-over-the-DS, where a station re-associates back to the same AP but
	 * skips the authentication flow, or if working with a driver that
	 * does not support full AP client state.
	 */
	if (!sta->added_unassoc)
		hostapd_drv_sta_remove(hapd, sta->addr);

#ifdef CONFIG_IEEE80211N
	if (sta->flags & WLAN_STA_HT)
		hostapd_get_ht_capab(hapd, sta->ht_capabilities, &ht_cap);
#endif /* CONFIG_IEEE80211N */
#ifdef CONFIG_IEEE80211AC
	if (sta->flags & WLAN_STA_VHT)
		hostapd_get_vht_capab(hapd, sta->vht_capabilities, &vht_cap);
#endif /* CONFIG_IEEE80211AC */

	/*
	 * Add the station with forced WLAN_STA_ASSOC flag. The sta->flags
	 * will be set when the ACK frame for the (Re)Association Response frame
	 * is processed (TX status driver event).
	 */
	if (hostapd_sta_add(hapd, sta->addr, sta->aid, sta->capability,
			    sta->supported_rates, sta->supported_rates_len,
			    sta->listen_interval,
			    sta->flags & WLAN_STA_HT ? &ht_cap : NULL,
			    sta->flags & WLAN_STA_VHT ? &vht_cap : NULL,
			    sta->flags | WLAN_STA_ASSOC, sta->qosinfo,
			    sta->vht_opmode, sta->p2p_ie ? 1 : 0,
			    sta->added_unassoc)) {
		hostapd_logger(hapd, sta->addr,
			       HOSTAPD_MODULE_IEEE80211, HOSTAPD_LEVEL_NOTICE,
			       "Could not %s STA to kernel driver",
			       sta->added_unassoc ? "set" : "add");

		if (sta->added_unassoc) {
			hostapd_drv_sta_remove(hapd, sta->addr);
			sta->added_unassoc = 0;
		}

		return -1;
	}

	sta->added_unassoc = 0;

	return 0;
}

//Зависимость handle_assoc()
static u16 send_assoc_resp(struct hostapd_data *hapd, struct sta_info *sta,
			   u16 status_code, int reassoc, const u8 *ies,
			   size_t ies_len)
{
	int send_len;
	u8 buf[sizeof(struct ieee80211_mgmt) + 1024];
	struct ieee80211_mgmt *reply;
	u8 *p;

	os_memset(buf, 0, sizeof(buf));
	reply = (struct ieee80211_mgmt *) buf;
	reply->frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_MGMT,
			     (reassoc ? WLAN_FC_STYPE_REASSOC_RESP :
			      WLAN_FC_STYPE_ASSOC_RESP));
	os_memcpy(reply->da, sta->addr, ETH_ALEN);
	os_memcpy(reply->sa, hapd->own_addr, ETH_ALEN);
	os_memcpy(reply->bssid, hapd->own_addr, ETH_ALEN);

	send_len = IEEE80211_HDRLEN;
	send_len += sizeof(reply->u.assoc_resp);
	reply->u.assoc_resp.capab_info =
		host_to_le16(hostapd_own_capab_info(hapd));
	reply->u.assoc_resp.status_code = host_to_le16(status_code);
	reply->u.assoc_resp.aid = host_to_le16(sta->aid | BIT(14) | BIT(15));
	/* Supported rates */
	p = hostapd_eid_supp_rates(hapd, reply->u.assoc_resp.variable);
	/* Extended supported rates */
	p = hostapd_eid_ext_supp_rates(hapd, p);

#ifdef CONFIG_IEEE80211R
	if (status_code == WLAN_STATUS_SUCCESS) {
		/* IEEE 802.11r: Mobility Domain Information, Fast BSS
		 * Transition Information, RSN, [RIC Response] */
		p = wpa_sm_write_assoc_resp_ies(sta->wpa_sm, p,
						buf + sizeof(buf) - p,
						sta->auth_alg, ies, ies_len);
	}
#endif /* CONFIG_IEEE80211R */

#ifdef CONFIG_IEEE80211W
	if (status_code == WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY)
		p = hostapd_eid_assoc_comeback_time(hapd, sta, p);
#endif /* CONFIG_IEEE80211W */

#ifdef CONFIG_IEEE80211N
	p = hostapd_eid_ht_capabilities(hapd, p);
	p = hostapd_eid_ht_operation(hapd, p);
#endif /* CONFIG_IEEE80211N */

#ifdef CONFIG_IEEE80211AC
	if (hapd->iconf->ieee80211ac && !hapd->conf->disable_11ac) {
		u32 nsts = 0, sta_nsts;

		if (hapd->conf->use_sta_nsts && sta->vht_capabilities) {
			struct ieee80211_vht_capabilities *capa;

			nsts = (hapd->iface->conf->vht_capab >>
				VHT_CAP_BEAMFORMEE_STS_OFFSET) & 7;
			capa = sta->vht_capabilities;
			sta_nsts = (le_to_host32(capa->vht_capabilities_info) >>
				    VHT_CAP_BEAMFORMEE_STS_OFFSET) & 7;

			if (nsts < sta_nsts)
				nsts = 0;
			else
				nsts = sta_nsts;
		}
		p = hostapd_eid_vht_capabilities(hapd, p, nsts);
		p = hostapd_eid_vht_operation(hapd, p);
	}
#endif /* CONFIG_IEEE80211AC */

	p = hostapd_eid_ext_capab(hapd, p);
	p = hostapd_eid_bss_max_idle_period(hapd, p);
	if (sta->qos_map_enabled)
		p = hostapd_eid_qos_map_set(hapd, p);

#ifdef CONFIG_FST
	if (hapd->iface->fst_ies) {
		os_memcpy(p, wpabuf_head(hapd->iface->fst_ies),
			  wpabuf_len(hapd->iface->fst_ies));
		p += wpabuf_len(hapd->iface->fst_ies);
	}
#endif /* CONFIG_FST */

#ifdef CONFIG_IEEE80211AC
	if (hapd->conf->vendor_vht && (sta->flags & WLAN_STA_VENDOR_VHT))
		p = hostapd_eid_vendor_vht(hapd, p);
#endif /* CONFIG_IEEE80211AC */

	if (sta->flags & WLAN_STA_WMM)
		p = hostapd_eid_wmm(hapd, p);

#ifdef CONFIG_WPS
	if ((sta->flags & WLAN_STA_WPS) ||
	    ((sta->flags & WLAN_STA_MAYBE_WPS) && hapd->conf->wpa)) {
		struct wpabuf *wps = wps_build_assoc_resp_ie();
		if (wps) {
			os_memcpy(p, wpabuf_head(wps), wpabuf_len(wps));
			p += wpabuf_len(wps);
			wpabuf_free(wps);
		}
	}
#endif /* CONFIG_WPS */

#ifdef CONFIG_P2P
	if (sta->p2p_ie && hapd->p2p_group) {
		struct wpabuf *p2p_resp_ie;
		enum p2p_status_code status;
		switch (status_code) {
		case WLAN_STATUS_SUCCESS:
			status = P2P_SC_SUCCESS;
			break;
		case WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA:
			status = P2P_SC_FAIL_LIMIT_REACHED;
			break;
		default:
			status = P2P_SC_FAIL_INVALID_PARAMS;
			break;
		}
		p2p_resp_ie = p2p_group_assoc_resp_ie(hapd->p2p_group, status);
		if (p2p_resp_ie) {
			os_memcpy(p, wpabuf_head(p2p_resp_ie),
				  wpabuf_len(p2p_resp_ie));
			p += wpabuf_len(p2p_resp_ie);
			wpabuf_free(p2p_resp_ie);
		}
	}
#endif /* CONFIG_P2P */

#ifdef CONFIG_P2P_MANAGER
	if (hapd->conf->p2p & P2P_MANAGE)
		p = hostapd_eid_p2p_manage(hapd, p);
#endif /* CONFIG_P2P_MANAGER */

	p = hostapd_eid_mbo(hapd, p, buf + sizeof(buf) - p);

	if (hapd->conf->assocresp_elements &&
	    (size_t) (buf + sizeof(buf) - p) >=
	    wpabuf_len(hapd->conf->assocresp_elements)) {
		os_memcpy(p, wpabuf_head(hapd->conf->assocresp_elements),
			  wpabuf_len(hapd->conf->assocresp_elements));
		p += wpabuf_len(hapd->conf->assocresp_elements);
	}

	send_len += p - reply->u.assoc_resp.variable;

	if (hostapd_drv_send_mlme(hapd, reply, send_len, 0) < 0) {
		wpa_printf(MSG_INFO, "Failed to send assoc resp: %s",
			   strerror(errno));
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	return WLAN_STATUS_SUCCESS;
}



enum ssid_match_result {
	NO_SSID_MATCH,
	EXACT_SSID_MATCH,
	WILDCARD_SSID_MATCH
};

static enum ssid_match_result ssid_match(struct hostapd_data *hapd,
					 const u8 *ssid, size_t ssid_len,
					 const u8 *ssid_list,
					 size_t ssid_list_len)
{
	const u8 *pos, *end;
	int wildcard = 0;

	if (ssid_len == 0)
		wildcard = 1;
	if (ssid_len == hapd->conf->ssid.ssid_len &&
	    os_memcmp(ssid, hapd->conf->ssid.ssid, ssid_len) == 0)
		return EXACT_SSID_MATCH;

	if (ssid_list == NULL)
		return wildcard ? WILDCARD_SSID_MATCH : NO_SSID_MATCH;

	pos = ssid_list;
	end = ssid_list + ssid_list_len;
	while (end - pos >= 1) {
		if (2 + pos[1] > end - pos)
			break;
		if (pos[1] == 0)
			wildcard = 1;
		if (pos[1] == hapd->conf->ssid.ssid_len &&
		    os_memcmp(pos + 2, hapd->conf->ssid.ssid, pos[1]) == 0)
			return EXACT_SSID_MATCH;
		pos += 2 + pos[1];
	}

	return wildcard ? WILDCARD_SSID_MATCH : NO_SSID_MATCH;
}

/*
void sta_track_expire(struct hostapd_iface *iface, int force)
{
	struct os_reltime now;
	struct hostapd_sta_info *info;

	if (!iface->num_sta_seen)
		return;

	os_get_reltime(&now);
	while ((info = dl_list_first(&iface->sta_seen, struct hostapd_sta_info,
				     list))) {
		if (!force &&
		    !os_reltime_expired(&now, &info->last_seen,
					iface->conf->track_sta_max_age))
			break;
		force = 0;

		wpa_printf(MSG_MSGDUMP, "%s: Expire STA tracking entry for "
			   MACSTR, iface->bss[0]->conf->iface,
			   MAC2STR(info->addr));
		dl_list_del(&info->list);
		iface->num_sta_seen--;
		sta_track_del(info);
	}
}
*/

//static struct hostapd_sta_info * sta_track_get(struct hostapd_iface *iface, //MANA
/*
struct hostapd_sta_info * sta_track_get(struct hostapd_iface *iface,
					       const u8 *addr)
{
	struct hostapd_sta_info *info;

	dl_list_for_each(info, &iface->sta_seen, struct hostapd_sta_info, list)
		if (os_memcmp(addr, info->addr, ETH_ALEN) == 0)
			return info;

	return NULL;
}
*/
/*
void sta_track_add(struct hostapd_iface *iface, const u8 *addr)
{
	struct hostapd_sta_info *info;

	info = sta_track_get(iface, addr);
	if (info) {
		/* Move the most recent entry to the end of the list *//*
		dl_list_del(&info->list);
		dl_list_add_tail(&iface->sta_seen, &info->list);
		os_get_reltime(&info->last_seen);
		return;
	}

	/* Add a new entry *//*
	info = os_zalloc(sizeof(*info));
	if (info == NULL)
		return;
	os_memcpy(info->addr, addr, ETH_ALEN);
	os_get_reltime(&info->last_seen);

	if (iface->num_sta_seen >= iface->conf->track_sta_max_num) {
		/* Expire oldest entry to make room for a new one *//*
		sta_track_expire(iface, 1);
	}

	wpa_printf(MSG_MSGDUMP, "%s: Add STA tracking entry for "
		   MACSTR, iface->bss[0]->conf->iface, MAC2STR(addr));
	dl_list_add_tail(&iface->sta_seen, &info->list);
	iface->num_sta_seen++;
}
*/
/*
struct hostapd_data *
sta_track_seen_on(struct hostapd_iface *iface, const u8 *addr,
		  const char *ifname)
{
	struct hapd_interfaces *interfaces = iface->interfaces;
	size_t i, j;

	for (i = 0; i < interfaces->count; i++) {
		struct hostapd_data *hapd = NULL;

		iface = interfaces->iface[i];
		for (j = 0; j < iface->num_bss; j++) {
			hapd = iface->bss[j];
			if (os_strcmp(ifname, hapd->conf->iface) == 0)
				break;
			hapd = NULL;
		}

		if (hapd && sta_track_get(iface, addr))
			return hapd;
	}

	return NULL;
}
*/

#ifdef CONFIG_TAXONOMY

void sta_track_claim_taxonomy_info_assoc(struct hostapd_iface *iface, const u8 *addr,
				   struct wpabuf **assoc_ie_taxonomy)
{
	struct sta_info *sta;

	sta = sta_track_get(iface, addr);
	if (!sta)
		return;

	wpabuf_free(*assoc_ie_taxonomy); /*change*/
	*assoc_ie_taxonomy = sta->assoc_ie_taxonomy;
	sta->assoc_ie_taxonomy = NULL;
}

#endif /* CONFIG_TAXONOMY */



void handle_assoc(struct hostapd_data *hapd,
			 const struct ieee80211_mgmt *mgmt, size_t len,
			 int reassoc)
{
	struct ieee802_11_elems elems;
	const u8 *ie;
	int noack;
	int ret;
	u16 csa_offs[2];
	size_t csa_offs_len;
	int iterate = 0; //MANA
	handle_type_assoc_probe = 1;
	u16 capab_info, listen_interval, seq_ctrl, fc;
	u16 resp = WLAN_STATUS_SUCCESS, reply_res;
	const u8 *pos;
	int left, i;
	struct sta_info *sta;
	enum ssid_match_result res;
	
	

	if (len < IEEE80211_HDRLEN + (reassoc ? sizeof(mgmt->u.reassoc_req) :
				      sizeof(mgmt->u.assoc_req))) {
		wpa_printf(MSG_INFO, "handle_assoc(reassoc=%d) - too short payload (len=%lu)",
			   reassoc, (unsigned long) len);
		return;
	}

#ifdef CONFIG_TESTING_OPTIONS
	if (reassoc) {
		if (hapd->iconf->ignore_reassoc_probability > 0.0 &&
		    drand48() < hapd->iconf->ignore_reassoc_probability) {
			wpa_printf(MSG_INFO,
				   "TESTING: ignoring reassoc request from "
				   MACSTR, MAC2STR(mgmt->sa));
			return;
		}
	} else {
		if (hapd->iconf->ignore_assoc_probability > 0.0 &&
		    drand48() < hapd->iconf->ignore_assoc_probability) {
			wpa_printf(MSG_INFO,
				   "TESTING: ignoring assoc request from "
				   MACSTR, MAC2STR(mgmt->sa));
			return;
		}
	}
#endif /* CONFIG_TESTING_OPTIONS */

	fc = le_to_host16(mgmt->frame_control);
	seq_ctrl = le_to_host16(mgmt->seq_ctrl);

	if (reassoc) {
		capab_info = le_to_host16(mgmt->u.reassoc_req.capab_info);
		listen_interval = le_to_host16(
			mgmt->u.reassoc_req.listen_interval);
		wpa_printf(MSG_DEBUG, "reassociation request: STA=" MACSTR
			   " capab_info=0x%02x listen_interval=%d current_ap="
			   MACSTR " seq_ctrl=0x%x%s",
			   MAC2STR(mgmt->sa), capab_info, listen_interval,
			   MAC2STR(mgmt->u.reassoc_req.current_ap),
			   seq_ctrl, (fc & WLAN_FC_RETRY) ? " retry" : "");
		left = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req));
		pos = mgmt->u.reassoc_req.variable;
	} else {
		capab_info = le_to_host16(mgmt->u.assoc_req.capab_info);
		listen_interval = le_to_host16(
			mgmt->u.assoc_req.listen_interval);
		wpa_printf(MSG_DEBUG, "association request: STA=" MACSTR
			   " capab_info=0x%02x listen_interval=%d "
			   "seq_ctrl=0x%x%s",
			   MAC2STR(mgmt->sa), capab_info, listen_interval,
			   seq_ctrl, (fc & WLAN_FC_RETRY) ? " retry" : "");
		left = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req));
		pos = mgmt->u.assoc_req.variable;
	}

	sta = ap_get_sta(hapd, mgmt->sa);
#ifdef CONFIG_IEEE80211R
	if (sta && sta->auth_alg == WLAN_AUTH_FT &&
	    (sta->flags & WLAN_STA_AUTH) == 0) {
		wpa_printf(MSG_DEBUG, "FT: Allow STA " MACSTR " to associate "
			   "prior to authentication since it is using "
			   "over-the-DS FT", MAC2STR(mgmt->sa));

		/*
		 * Mark station as authenticated, to avoid adding station
		 * entry in the driver as associated and not authenticated
		 */
		sta->flags |= WLAN_STA_AUTH;
	} else
#endif /* CONFIG_IEEE80211R */
	if (sta == NULL || (sta->flags & WLAN_STA_AUTH) == 0) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "Station tried to "
			       "associate before authentication "
			       "(aid=%d flags=0x%x)",
			       sta ? sta->aid : -1,
			       sta ? sta->flags : 0);
		send_deauth(hapd, mgmt->sa,
			    WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
		return;
	}

	if ((fc & WLAN_FC_RETRY) &&
	    sta->last_seq_ctrl != WLAN_INVALID_MGMT_SEQ &&
	    sta->last_seq_ctrl == seq_ctrl &&
	    sta->last_subtype == reassoc ? WLAN_FC_STYPE_REASSOC_REQ :
	    WLAN_FC_STYPE_ASSOC_REQ) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "Drop repeated association frame seq_ctrl=0x%x",
			       seq_ctrl);
		return;
	}
	sta->last_seq_ctrl = seq_ctrl;
	sta->last_subtype = reassoc ? WLAN_FC_STYPE_REASSOC_REQ :
		WLAN_FC_STYPE_ASSOC_REQ;

	if (hapd->tkip_countermeasures) {
		resp = WLAN_REASON_MICHAEL_MIC_FAILURE;
		goto fail;
	}

	if (listen_interval > hapd->conf->max_listen_interval) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "Too large Listen Interval (%d)",
			       listen_interval);
		resp = WLAN_STATUS_ASSOC_DENIED_LISTEN_INT_TOO_LARGE;
		goto fail;
	}

#ifdef CONFIG_MBO
	if (hapd->conf->mbo_enabled && hapd->mbo_assoc_disallow) {
		resp = WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
		goto fail;
	}
#endif /* CONFIG_MBO */

	/*
	 * sta->capability is used in check_assoc_ies() for RRM enabled
	 * capability element.
	 */
	sta->capability = capab_info;

	/* followed by SSID and Supported rates; and HT capabilities if 802.11n
	 * is used */
	resp = check_assoc_ies(hapd, sta, pos, left, reassoc);
	if (resp != WLAN_STATUS_SUCCESS)
		goto fail;

	if (hostapd_get_aid(hapd, sta) < 0) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "No room for more AIDs");
		resp = WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
		goto fail;
	}

	sta->listen_interval = listen_interval;

	if (hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G)
		sta->flags |= WLAN_STA_NONERP;
	for (i = 0; i < sta->supported_rates_len; i++) {
		if ((sta->supported_rates[i] & 0x7f) > 22) {
			sta->flags &= ~WLAN_STA_NONERP;
			break;
		}
	}
	if (sta->flags & WLAN_STA_NONERP && !sta->nonerp_set) {
		sta->nonerp_set = 1;
		hapd->iface->num_sta_non_erp++;
		if (hapd->iface->num_sta_non_erp == 1)
			ieee802_11_set_beacons(hapd->iface);
	}

	if (!(sta->capability & WLAN_CAPABILITY_SHORT_SLOT_TIME) &&
	    !sta->no_short_slot_time_set) {
		sta->no_short_slot_time_set = 1;
		hapd->iface->num_sta_no_short_slot_time++;
		if (hapd->iface->current_mode->mode ==
		    HOSTAPD_MODE_IEEE80211G &&
		    hapd->iface->num_sta_no_short_slot_time == 1)
			ieee802_11_set_beacons(hapd->iface);
	}

	if (sta->capability & WLAN_CAPABILITY_SHORT_PREAMBLE)
		sta->flags |= WLAN_STA_SHORT_PREAMBLE;
	else
		sta->flags &= ~WLAN_STA_SHORT_PREAMBLE;

	if (!(sta->capability & WLAN_CAPABILITY_SHORT_PREAMBLE) &&
	    !sta->no_short_preamble_set) {
		sta->no_short_preamble_set = 1;
		hapd->iface->num_sta_no_short_preamble++;
		if (hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G
		    && hapd->iface->num_sta_no_short_preamble == 1)
			ieee802_11_set_beacons(hapd->iface);
	}

#ifdef CONFIG_IEEE80211N
	update_ht_state(hapd, sta);
#endif /* CONFIG_IEEE80211N */

	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		       "association OK (aid %d)", sta->aid);
	/* Station will be marked associated, after it acknowledges AssocResp
	 */
	sta->flags |= WLAN_STA_ASSOC_REQ_OK;

#ifdef CONFIG_IEEE80211W
	if ((sta->flags & WLAN_STA_MFP) && sta->sa_query_timed_out) {
		wpa_printf(MSG_DEBUG, "Allowing %sassociation after timed out "
			   "SA Query procedure", reassoc ? "re" : "");
		/* TODO: Send a protected Disassociate frame to the STA using
		 * the old key and Reason Code "Previous Authentication no
		 * longer valid". Make sure this is only sent protected since
		 * unprotected frame would be received by the STA that is now
		 * trying to associate.
		 */
	}
#endif /* CONFIG_IEEE80211W */

	/* Make sure that the previously registered inactivity timer will not
	 * remove the STA immediately. */
	sta->timeout_next = STA_NULLFUNC;

#ifdef CONFIG_TAXONOMY
	
	taxonomy_sta_info_assoc_req(hapd, sta, pos, left);
	wpa_printf(MSG_MSGDUMP, "MANA ASSOC TAXONOMY STA '%s'", pos);
	
	
#endif /* CONFIG_TAXONOMY */

res = ssid_match(hapd, elems.ssid, elems.ssid_len,
			 elems.ssid_list, elems.ssid_list_len);
	//MANA START
 	// todo handle ssid_list see ssid_match for code
 	// todo change emit code below (global flag?)
	if (!hapd->iconf->enable_mana && res == NO_SSID_MATCH) {
		if (!(mgmt->da[0] & 0x01)) {
			wpa_printf(MSG_MSGDUMP, "Probe Request from " MACSTR
				   " for foreign SSID '%s' (DA " MACSTR ")%s",
				   MAC2STR(mgmt->sa),
				   wpa_ssid_txt(elems.ssid, elems.ssid_len),
				   MAC2STR(mgmt->da),
				   elems.ssid_list ? " (SSID list)" : "");
		}
		return;
	} else if (hapd->iconf->enable_mana) {
		if (res == WILDCARD_SSID_MATCH) {
			//Broadcast probe no need to record SSID or STA
			wpa_printf(MSG_DEBUG,"MANA - <<<redact>>> Broadcast probe request from " MACSTR "",MAC2STR(mgmt->sa));
			iterate = 1; //iterate through hash emitting multiple probe responses
			log_ssid(hapd, (const u8 *)"<Broadcast>", 11, mgmt->sa);
		} else {
			//Directed probe
			struct mana_ssid *newssid = NULL;
			struct mana_mac *newsta = NULL;
			if (hapd->iconf->mana_loud) {
				//Loud mode check ssidhash
				HASH_FIND_STR(mana_ssidhash, wpa_ssid_txt(elems.ssid, elems.ssid_len), newssid);
			} else {
				//Not loud mode, check if the STA probing is in our hash
				HASH_FIND(hh,mana_machash, mgmt->sa, 6, newsta);
				if (newsta == NULL) { //STA MAC not seen before adding to hash
					wpa_printf(MSG_DEBUG, "MANA - Adding STA " MACSTR " to the hash.", MAC2STR(mgmt->sa));
					newsta = (struct mana_mac*)os_malloc(sizeof(struct mana_mac));
					os_memcpy(newsta->sta_addr, mgmt->sa, ETH_ALEN);
					newsta->ssids = NULL;
					HASH_ADD(hh,mana_machash, sta_addr, 6, newsta);
				}
				HASH_FIND_STR(newsta->ssids, wpa_ssid_txt(elems.ssid, elems.ssid_len), newssid);
			}

			if (newssid == NULL) {
				//Probed for SSID not found (and not Broadcast) add SSID to hash
				wpa_printf(MSG_DEBUG, "MANA - Adding SSID %s(%d) from STA " MACSTR " to the hash.", wpa_ssid_txt(elems.ssid, elems.ssid_len), elems.ssid_len, MAC2STR(mgmt->sa));
				struct mana_ssid *newssid = os_malloc(sizeof(struct mana_ssid));
				os_memcpy(newssid->ssid_txt, wpa_ssid_txt(elems.ssid, elems.ssid_len), elems.ssid_len+1);
				os_memcpy(newssid->ssid, elems.ssid, elems.ssid_len);
				newssid->ssid_len = elems.ssid_len;
				if (hapd->iconf->mana_loud)
					HASH_ADD_STR(mana_ssidhash, ssid_txt, newssid);
				else
					HASH_ADD_STR(newsta->ssids, ssid_txt, newssid);
			}
 			wpa_printf(MSG_INFO,"MANA - Directed assoc request for SSID '%s' from " MACSTR "",wpa_ssid_txt(elems.ssid, elems.ssid_len),MAC2STR(mgmt->sa));
			log_ssid(hapd, elems.ssid, elems.ssid_len, mgmt->sa);
 		}
	}

 fail:
	/*
	 * In case of a successful response, add the station to the driver.
	 * Otherwise, the kernel may ignore Data frames before we process the
	 * ACK frame (TX status). In case of a failure, this station will be
	 * removed.
	 *
	 * Note that this is not compliant with the IEEE 802.11 standard that
	 * states that a non-AP station should transition into the
	 * authenticated/associated state only after the station acknowledges
	 * the (Re)Association Response frame. However, still do this as:
	 *
	 * 1. In case the station does not acknowledge the (Re)Association
	 *    Response frame, it will be removed.
	 * 2. Data frames will be dropped in the kernel until the station is
	 *    set into authorized state, and there are no significant known
	 *    issues with processing other non-Data Class 3 frames during this
	 *    window.
	 */
	if (resp == WLAN_STATUS_SUCCESS && add_associated_sta(hapd, sta))
		resp = WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;

	reply_res = send_assoc_resp(hapd, sta, resp, reassoc, pos, left);

	/*
	 * Remove the station in case tranmission of a success response fails
	 * (the STA was added associated to the driver) or if the station was
	 * previously added unassociated.
	 */
	if ((reply_res != WLAN_STATUS_SUCCESS &&
	     resp == WLAN_STATUS_SUCCESS) || sta->added_unassoc) {
		hostapd_drv_sta_remove(hapd, sta->addr);
		sta->added_unassoc = 0;
	}
}


#endif /* CONFIG_NATIVE_WINDOWS */