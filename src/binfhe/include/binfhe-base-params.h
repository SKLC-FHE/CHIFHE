//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
 * Custom Modifications:
 * - [This code is the implementation of the algorithm in the paper https://eprint.iacr.org/2023/1564]
 * 
 * This modified section follows the terms of the original BSD 2-Clause License.
 * Other modifications are provided under the terms of the BSD 2-Clause License.
 * See the BSD 2-Clause License text below:
 */


//==================================================================================
// Additional BSD License for Custom Modifications:
//
// Copyright (c) 2023 Binwu Xiang,Kaixing Wang and other contributors
//
// All rights reserved.
//
// Author TPOC: wangkaixing22@mails.ucas.ac.cn
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
#ifndef _BINFHE_BASE_PARAMS_H_
#define _BINFHE_BASE_PARAMS_H_

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include "binfhe-constants.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-cryptoparameters.h"
#include "rgsw-cryptoparameters.h"
#include "vntru-cryptoparameters.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class BinFHECryptoParams : public Serializable {
private:
    // shared pointer to an instance of LWECryptoParams
    std::shared_ptr<LWECryptoParams> m_LWEParams{nullptr};

    // shared pointer to an instance of RGSWCryptoParams
    std::shared_ptr<RingGSWCryptoParams> m_RGSWParams{nullptr};

    // wkx
    // shared pointer to an instance of VNTRUCryptoParams
    std::shared_ptr<VectorNTRUCryptoParams> m_VNTRUParams{nullptr};
public:
    BinFHECryptoParams() = default;

    /**
   * Main constructor for BinFHECryptoParams
   *
   * @param lweparams a shared poiter to an instance of LWECryptoParams
   * @param rgswparams a shared poiter to an instance of RingGSWCryptoParams
   */
    //带参数的构造函数，参数为智能指针
    BinFHECryptoParams(const std::shared_ptr<LWECryptoParams>& lweparams,
                       const std::shared_ptr<RingGSWCryptoParams>& rgswparams)
        : m_LWEParams(lweparams), m_RGSWParams(rgswparams) {}


    //wkx
    BinFHECryptoParams(const std::shared_ptr<LWECryptoParams>& lweparams,
                    const std::shared_ptr<VectorNTRUCryptoParams>& vntruparams)
        : m_LWEParams(lweparams), m_VNTRUParams(vntruparams) {}

    /**
   * Getter for LWE params
   * @return
   */
    const std::shared_ptr<LWECryptoParams>& GetLWEParams() const {
        return m_LWEParams;
    }

    /**
   * Getter for RingGSW params
   * @return
   */
    const std::shared_ptr<RingGSWCryptoParams>& GetRingGSWParams() const {
        return m_RGSWParams;
    }

    /**
   * wkx 
   * Getter for VectorNTRU params
   * @return
   */
    const std::shared_ptr<VectorNTRUCryptoParams>& GetVectorNTRUParams() const {
        return m_VNTRUParams;
    }

    /**
   * Compare two BinFHE sets of parameters
   * wkx
   * @return
   */
    bool operator==(const BinFHECryptoParams& other) const {
        return *m_LWEParams == *other.m_LWEParams && *m_RGSWParams == *other.m_RGSWParams && *m_VNTRUParams == *other.m_VNTRUParams;
    }

    bool operator!=(const BinFHECryptoParams& other) const {
        return !(*this == other);
    }

    /**
     * @brief 
     * 使用了 Cereal 库进行序列化。序列化是将对象或数据结构转换为一种易于存储或传输的格式，以便稍后进行重建。
     * @tparam Archive 
     * @param ar 
     * @param version 
     */
    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        //使用 Cereal 序列化了成员变量 m_LWEParams
        ar(::cereal::make_nvp("lweparams", m_LWEParams));
        ar(::cereal::make_nvp("rgswparams", m_RGSWParams));
        //wkx
        ar(::cereal::make_nvp("vntruparams", m_VNTRUParams));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("lweparams", m_LWEParams));
        ar(::cereal::make_nvp("rgswparams", m_RGSWParams));
        //wkx
        ar(::cereal::make_nvp("vntruparams", m_VNTRUParams));
    }

    std::string SerializedObjectName() const override {
        return "BinFHECryptoParams";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }


};

}  // namespace lbcrypto

#endif  // _BINFHE_BASE_PARAMS_H_
