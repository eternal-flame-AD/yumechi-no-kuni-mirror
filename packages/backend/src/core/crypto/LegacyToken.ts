/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { LU_CHARS, secureRndstr } from '@/misc/secure-rndstr.js';

export const generateNativeUserToken = () => secureRndstr(16);
export const generateNativeAppToken = () => secureRndstr(32);

const LEGACY_USER_TOKEN_CHARS_REGEX = new RegExp(`^[${LU_CHARS}]{16}$`);
const LEGACY_APP_TOKEN_CHARS_REGEX = new RegExp(`^[${LU_CHARS}]{32}$`);

export const isLegacyUserToken = (token: string) => LEGACY_USER_TOKEN_CHARS_REGEX.test(token);
export const isLegacyAppToken = (token: string) => LEGACY_APP_TOKEN_CHARS_REGEX.test(token);
