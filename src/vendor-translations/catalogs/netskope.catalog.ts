import type { VendorCatalog } from '../catalog-types'
import catalogJson from './netskope-catalog-v0.1.json'

export const NETSKOPE_CATALOG = catalogJson as unknown as VendorCatalog
export const CATALOG_VERSION  = NETSKOPE_CATALOG.vendor_catalog.catalog_version
