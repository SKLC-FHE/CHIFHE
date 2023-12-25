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
#ifndef _VNTRU_EVAL_KEY_H_
#define _VNTRU_EVAL_KEY_H_

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "lwe-cryptoparameters.h"

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>


namespace lbcrypto {

class VectorNTRUEvalKeyImpl;
using VectorNTRUEvalKey      = std::shared_ptr<VectorNTRUEvalKeyImpl>;
using ConstVectorNTRUEvalKey = const std::shared_ptr<const VectorNTRUEvalKeyImpl>;


class VectorNTRUEvalKeyImpl : public Serializable {
private:
    std::vector<NativePoly> m_elements;
public:
    VectorNTRUEvalKeyImpl() = default;

    VectorNTRUEvalKeyImpl(uint32_t colSize) noexcept
        : m_elements(std::vector<NativePoly>(colSize)) {}

    explicit VectorNTRUEvalKeyImpl(const std::vector<NativePoly>& elements) : m_elements(elements) {}

    VectorNTRUEvalKeyImpl(const VectorNTRUEvalKeyImpl& rhs) : m_elements(rhs.m_elements) {}

    VectorNTRUEvalKeyImpl(VectorNTRUEvalKeyImpl&& rhs) noexcept : m_elements(std::move(rhs.m_elements)) {}

    VectorNTRUEvalKeyImpl& operator=(const VectorNTRUEvalKeyImpl& rhs) {
        VectorNTRUEvalKeyImpl::m_elements = rhs.m_elements;
        return *this;
    }

    VectorNTRUEvalKeyImpl& operator=(VectorNTRUEvalKeyImpl&& rhs) noexcept {
        VectorNTRUEvalKeyImpl::m_elements = std::move(rhs.m_elements);
        return *this;
    }

    const std::vector<NativePoly>& GetElements() const {
        return m_elements;
    }

    void SetElements(const std::vector<NativePoly>& elements) {
        m_elements = elements;
    }

    /**
   * Switches between COEFFICIENT and Format::EVALUATION polynomial
   * representations using NTT
   */
    void SetFormat(const Format format) {
     
            auto& l1 = m_elements;
            for (size_t j = 0; j < l1.size(); ++j){
                l1[j].SetFormat(format);
        }
    }

    NativePoly& operator[](uint32_t i) {
        return m_elements[i];
    }

    const NativePoly& operator[](uint32_t i) const {
        return m_elements[i];
    }

    bool operator==(const VectorNTRUEvalKeyImpl& other) const {
        if (m_elements.size() != other.m_elements.size())
            return false;
        return true;
    }

    bool operator!=(const VectorNTRUEvalKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elements", m_elements));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elements", m_elements));
    }

    std::string SerializedObjectName() const override {
        return "VectorNTRUEvalKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }


};

} // namespace lbcrypto

#endif  // _VNTRU_EVAL_KEY_H_